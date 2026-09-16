rule TTP_XOR_QUAD_CurrentVersionRun_e444 {
  strings:
    $key_e444 = { b7 2b [2] 93 25 [2] b8 09 [2] 96 2b [2] 82 30 [2] 8d 2a [2] 93 37 [2] 91 36 [2] 8a 30 [2] 96 37 [2] 8a 18 }

  condition:
    any of them
}