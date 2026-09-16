rule TTP_XOR_QUAD_CurrentVersionRun_6227 {
  strings:
    $key_6227 = { 31 48 [2] 15 46 [2] 3e 6a [2] 10 48 [2] 04 53 [2] 0b 49 [2] 15 54 [2] 17 55 [2] 0c 53 [2] 10 54 [2] 0c 7b }

  condition:
    any of them
}