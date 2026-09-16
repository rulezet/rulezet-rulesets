rule TTP_XOR_QUAD_CurrentVersionRun_62e7 {
  strings:
    $key_62e7 = { 31 88 [2] 15 86 [2] 3e aa [2] 10 88 [2] 04 93 [2] 0b 89 [2] 15 94 [2] 17 95 [2] 0c 93 [2] 10 94 [2] 0c bb }

  condition:
    any of them
}