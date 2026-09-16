rule TTP_XOR_QUAD_CurrentVersionRun_7132 {
  strings:
    $key_7132 = { 22 5d [2] 06 53 [2] 2d 7f [2] 03 5d [2] 17 46 [2] 18 5c [2] 06 41 [2] 04 40 [2] 1f 46 [2] 03 41 [2] 1f 6e }

  condition:
    any of them
}