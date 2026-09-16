rule TTP_XOR_QUAD_CurrentVersionRun_8a80 {
  strings:
    $key_8a80 = { d9 ef [2] fd e1 [2] d6 cd [2] f8 ef [2] ec f4 [2] e3 ee [2] fd f3 [2] ff f2 [2] e4 f4 [2] f8 f3 [2] e4 dc }

  condition:
    any of them
}