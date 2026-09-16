rule TTP_XOR_QUAD_CurrentVersionRun_8a8a {
  strings:
    $key_8a8a = { d9 e5 [2] fd eb [2] d6 c7 [2] f8 e5 [2] ec fe [2] e3 e4 [2] fd f9 [2] ff f8 [2] e4 fe [2] f8 f9 [2] e4 d6 }

  condition:
    any of them
}