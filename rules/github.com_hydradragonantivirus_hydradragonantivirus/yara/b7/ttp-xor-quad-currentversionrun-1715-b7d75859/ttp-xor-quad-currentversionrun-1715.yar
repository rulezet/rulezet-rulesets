rule TTP_XOR_QUAD_CurrentVersionRun_1715 {
  strings:
    $key_1715 = { 44 7a [2] 60 74 [2] 4b 58 [2] 65 7a [2] 71 61 [2] 7e 7b [2] 60 66 [2] 62 67 [2] 79 61 [2] 65 66 [2] 79 49 }

  condition:
    any of them
}