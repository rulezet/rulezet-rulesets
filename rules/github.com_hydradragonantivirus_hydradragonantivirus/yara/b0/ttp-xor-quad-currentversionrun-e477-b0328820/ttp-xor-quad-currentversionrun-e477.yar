rule TTP_XOR_QUAD_CurrentVersionRun_e477 {
  strings:
    $key_e477 = { b7 18 [2] 93 16 [2] b8 3a [2] 96 18 [2] 82 03 [2] 8d 19 [2] 93 04 [2] 91 05 [2] 8a 03 [2] 96 04 [2] 8a 2b }

  condition:
    any of them
}