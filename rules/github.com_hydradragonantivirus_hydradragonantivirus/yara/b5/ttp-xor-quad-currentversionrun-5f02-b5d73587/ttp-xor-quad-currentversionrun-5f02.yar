rule TTP_XOR_QUAD_CurrentVersionRun_5f02 {
  strings:
    $key_5f02 = { 0c 6d [2] 28 63 [2] 03 4f [2] 2d 6d [2] 39 76 [2] 36 6c [2] 28 71 [2] 2a 70 [2] 31 76 [2] 2d 71 [2] 31 5e }

  condition:
    any of them
}