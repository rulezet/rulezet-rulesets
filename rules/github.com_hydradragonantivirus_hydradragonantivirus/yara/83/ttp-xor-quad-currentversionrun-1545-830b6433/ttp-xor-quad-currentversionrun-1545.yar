rule TTP_XOR_QUAD_CurrentVersionRun_1545 {
  strings:
    $key_1545 = { 46 2a [2] 62 24 [2] 49 08 [2] 67 2a [2] 73 31 [2] 7c 2b [2] 62 36 [2] 60 37 [2] 7b 31 [2] 67 36 [2] 7b 19 }

  condition:
    any of them
}