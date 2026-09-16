rule TTP_XOR_QUAD_CurrentVersionRun_5a02 {
  strings:
    $key_5a02 = { 09 6d [2] 2d 63 [2] 06 4f [2] 28 6d [2] 3c 76 [2] 33 6c [2] 2d 71 [2] 2f 70 [2] 34 76 [2] 28 71 [2] 34 5e }

  condition:
    any of them
}