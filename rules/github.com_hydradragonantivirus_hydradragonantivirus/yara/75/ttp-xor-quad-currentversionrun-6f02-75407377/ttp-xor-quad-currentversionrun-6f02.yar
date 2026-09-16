rule TTP_XOR_QUAD_CurrentVersionRun_6f02 {
  strings:
    $key_6f02 = { 3c 6d [2] 18 63 [2] 33 4f [2] 1d 6d [2] 09 76 [2] 06 6c [2] 18 71 [2] 1a 70 [2] 01 76 [2] 1d 71 [2] 01 5e }

  condition:
    any of them
}