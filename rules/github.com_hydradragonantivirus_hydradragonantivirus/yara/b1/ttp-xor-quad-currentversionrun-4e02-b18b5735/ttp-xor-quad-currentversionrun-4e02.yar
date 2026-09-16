rule TTP_XOR_QUAD_CurrentVersionRun_4e02 {
  strings:
    $key_4e02 = { 1d 6d [2] 39 63 [2] 12 4f [2] 3c 6d [2] 28 76 [2] 27 6c [2] 39 71 [2] 3b 70 [2] 20 76 [2] 3c 71 [2] 20 5e }

  condition:
    any of them
}