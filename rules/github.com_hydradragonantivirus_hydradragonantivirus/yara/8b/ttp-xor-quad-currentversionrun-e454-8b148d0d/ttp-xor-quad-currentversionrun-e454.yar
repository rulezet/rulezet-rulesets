rule TTP_XOR_QUAD_CurrentVersionRun_e454 {
  strings:
    $key_e454 = { b7 3b [2] 93 35 [2] b8 19 [2] 96 3b [2] 82 20 [2] 8d 3a [2] 93 27 [2] 91 26 [2] 8a 20 [2] 96 27 [2] 8a 08 }

  condition:
    any of them
}