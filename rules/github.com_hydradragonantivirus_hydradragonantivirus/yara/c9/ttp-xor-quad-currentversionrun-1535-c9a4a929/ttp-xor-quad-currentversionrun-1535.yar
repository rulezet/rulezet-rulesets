rule TTP_XOR_QUAD_CurrentVersionRun_1535 {
  strings:
    $key_1535 = { 46 5a [2] 62 54 [2] 49 78 [2] 67 5a [2] 73 41 [2] 7c 5b [2] 62 46 [2] 60 47 [2] 7b 41 [2] 67 46 [2] 7b 69 }

  condition:
    any of them
}