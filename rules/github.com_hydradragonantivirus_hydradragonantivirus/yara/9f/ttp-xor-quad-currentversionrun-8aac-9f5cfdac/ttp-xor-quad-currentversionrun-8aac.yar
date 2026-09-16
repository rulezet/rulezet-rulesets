rule TTP_XOR_QUAD_CurrentVersionRun_8aac {
  strings:
    $key_8aac = { d9 c3 [2] fd cd [2] d6 e1 [2] f8 c3 [2] ec d8 [2] e3 c2 [2] fd df [2] ff de [2] e4 d8 [2] f8 df [2] e4 f0 }

  condition:
    any of them
}