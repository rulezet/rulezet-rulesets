rule TTP_XOR_QUAD_CurrentVersionRun_7611 {
  strings:
    $key_7611 = { 25 7e [2] 01 70 [2] 2a 5c [2] 04 7e [2] 10 65 [2] 1f 7f [2] 01 62 [2] 03 63 [2] 18 65 [2] 04 62 [2] 18 4d }

  condition:
    any of them
}