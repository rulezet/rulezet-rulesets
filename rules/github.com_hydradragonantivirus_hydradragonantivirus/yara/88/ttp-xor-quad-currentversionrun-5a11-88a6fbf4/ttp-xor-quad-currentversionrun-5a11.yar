rule TTP_XOR_QUAD_CurrentVersionRun_5a11 {
  strings:
    $key_5a11 = { 09 7e [2] 2d 70 [2] 06 5c [2] 28 7e [2] 3c 65 [2] 33 7f [2] 2d 62 [2] 2f 63 [2] 34 65 [2] 28 62 [2] 34 4d }

  condition:
    any of them
}