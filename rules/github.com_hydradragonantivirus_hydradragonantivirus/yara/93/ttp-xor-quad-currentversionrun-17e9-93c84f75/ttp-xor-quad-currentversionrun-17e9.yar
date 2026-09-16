rule TTP_XOR_QUAD_CurrentVersionRun_17e9 {
  strings:
    $key_17e9 = { 44 86 [2] 60 88 [2] 4b a4 [2] 65 86 [2] 71 9d [2] 7e 87 [2] 60 9a [2] 62 9b [2] 79 9d [2] 65 9a [2] 79 b5 }

  condition:
    any of them
}