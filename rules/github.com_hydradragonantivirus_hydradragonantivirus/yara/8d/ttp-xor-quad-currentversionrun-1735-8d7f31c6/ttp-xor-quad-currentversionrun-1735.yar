rule TTP_XOR_QUAD_CurrentVersionRun_1735 {
  strings:
    $key_1735 = { 44 5a [2] 60 54 [2] 4b 78 [2] 65 5a [2] 71 41 [2] 7e 5b [2] 60 46 [2] 62 47 [2] 79 41 [2] 65 46 [2] 79 69 }

  condition:
    any of them
}