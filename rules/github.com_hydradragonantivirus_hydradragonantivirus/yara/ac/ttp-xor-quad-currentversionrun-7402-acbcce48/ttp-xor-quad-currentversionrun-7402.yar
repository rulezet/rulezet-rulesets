rule TTP_XOR_QUAD_CurrentVersionRun_7402 {
  strings:
    $key_7402 = { 27 6d [2] 03 63 [2] 28 4f [2] 06 6d [2] 12 76 [2] 1d 6c [2] 03 71 [2] 01 70 [2] 1a 76 [2] 06 71 [2] 1a 5e }

  condition:
    any of them
}