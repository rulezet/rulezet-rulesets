rule TTP_XOR_QUAD_CurrentVersionRun_6402 {
  strings:
    $key_6402 = { 37 6d [2] 13 63 [2] 38 4f [2] 16 6d [2] 02 76 [2] 0d 6c [2] 13 71 [2] 11 70 [2] 0a 76 [2] 16 71 [2] 0a 5e }

  condition:
    any of them
}