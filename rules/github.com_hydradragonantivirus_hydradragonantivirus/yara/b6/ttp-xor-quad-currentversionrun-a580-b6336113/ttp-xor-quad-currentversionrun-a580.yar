rule TTP_XOR_QUAD_CurrentVersionRun_a580 {
  strings:
    $key_a580 = { f6 ef [2] d2 e1 [2] f9 cd [2] d7 ef [2] c3 f4 [2] cc ee [2] d2 f3 [2] d0 f2 [2] cb f4 [2] d7 f3 [2] cb dc }

  condition:
    any of them
}