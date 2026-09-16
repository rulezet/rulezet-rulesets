rule TTP_XOR_QUAD_CurrentVersionRun_1714 {
  strings:
    $key_1714 = { 44 7b [2] 60 75 [2] 4b 59 [2] 65 7b [2] 71 60 [2] 7e 7a [2] 60 67 [2] 62 66 [2] 79 60 [2] 65 67 [2] 79 48 }

  condition:
    any of them
}