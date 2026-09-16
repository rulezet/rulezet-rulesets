rule TTP_XOR_QUAD_CurrentVersionRun_5211 {
  strings:
    $key_5211 = { 01 7e [2] 25 70 [2] 0e 5c [2] 20 7e [2] 34 65 [2] 3b 7f [2] 25 62 [2] 27 63 [2] 3c 65 [2] 20 62 [2] 3c 4d }

  condition:
    any of them
}