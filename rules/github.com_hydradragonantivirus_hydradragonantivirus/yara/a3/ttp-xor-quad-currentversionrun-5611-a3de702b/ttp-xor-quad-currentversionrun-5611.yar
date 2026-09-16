rule TTP_XOR_QUAD_CurrentVersionRun_5611 {
  strings:
    $key_5611 = { 05 7e [2] 21 70 [2] 0a 5c [2] 24 7e [2] 30 65 [2] 3f 7f [2] 21 62 [2] 23 63 [2] 38 65 [2] 24 62 [2] 38 4d }

  condition:
    any of them
}