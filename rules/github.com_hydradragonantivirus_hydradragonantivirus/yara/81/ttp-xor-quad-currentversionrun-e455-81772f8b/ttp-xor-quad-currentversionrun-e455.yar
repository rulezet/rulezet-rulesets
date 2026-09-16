rule TTP_XOR_QUAD_CurrentVersionRun_e455 {
  strings:
    $key_e455 = { b7 3a [2] 93 34 [2] b8 18 [2] 96 3a [2] 82 21 [2] 8d 3b [2] 93 26 [2] 91 27 [2] 8a 21 [2] 96 26 [2] 8a 09 }

  condition:
    any of them
}