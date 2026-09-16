rule TTP_XOR_QUAD_CurrentVersionRun_e478 {
  strings:
    $key_e478 = { b7 17 [2] 93 19 [2] b8 35 [2] 96 17 [2] 82 0c [2] 8d 16 [2] 93 0b [2] 91 0a [2] 8a 0c [2] 96 0b [2] 8a 24 }

  condition:
    any of them
}