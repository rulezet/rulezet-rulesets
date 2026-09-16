rule TTP_XOR_QUAD_CurrentVersionRun_5727 {
  strings:
    $key_5727 = { 04 48 [2] 20 46 [2] 0b 6a [2] 25 48 [2] 31 53 [2] 3e 49 [2] 20 54 [2] 22 55 [2] 39 53 [2] 25 54 [2] 39 7b }

  condition:
    any of them
}