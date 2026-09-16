rule TTP_XOR_QUAD_CurrentVersionRun_8a85 {
  strings:
    $key_8a85 = { d9 ea [2] fd e4 [2] d6 c8 [2] f8 ea [2] ec f1 [2] e3 eb [2] fd f6 [2] ff f7 [2] e4 f1 [2] f8 f6 [2] e4 d9 }

  condition:
    any of them
}