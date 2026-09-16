rule TTP_XOR_QUAD_CurrentVersionRun_8ae1 {
  strings:
    $key_8ae1 = { d9 8e [2] fd 80 [2] d6 ac [2] f8 8e [2] ec 95 [2] e3 8f [2] fd 92 [2] ff 93 [2] e4 95 [2] f8 92 [2] e4 bd }

  condition:
    any of them
}