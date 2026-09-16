rule TTP_XOR_QUAD_CurrentVersionRun_8af6 {
  strings:
    $key_8af6 = { d9 99 [2] fd 97 [2] d6 bb [2] f8 99 [2] ec 82 [2] e3 98 [2] fd 85 [2] ff 84 [2] e4 82 [2] f8 85 [2] e4 aa }

  condition:
    any of them
}