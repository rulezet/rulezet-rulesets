rule TTP_XOR_QUAD_CurrentVersionRun_8af0 {
  strings:
    $key_8af0 = { d9 9f [2] fd 91 [2] d6 bd [2] f8 9f [2] ec 84 [2] e3 9e [2] fd 83 [2] ff 82 [2] e4 84 [2] f8 83 [2] e4 ac }

  condition:
    any of them
}