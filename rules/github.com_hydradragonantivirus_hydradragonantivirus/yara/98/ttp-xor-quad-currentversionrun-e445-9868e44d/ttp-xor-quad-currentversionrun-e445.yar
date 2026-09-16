rule TTP_XOR_QUAD_CurrentVersionRun_e445 {
  strings:
    $key_e445 = { b7 2a [2] 93 24 [2] b8 08 [2] 96 2a [2] 82 31 [2] 8d 2b [2] 93 36 [2] 91 37 [2] 8a 31 [2] 96 36 [2] 8a 19 }

  condition:
    any of them
}