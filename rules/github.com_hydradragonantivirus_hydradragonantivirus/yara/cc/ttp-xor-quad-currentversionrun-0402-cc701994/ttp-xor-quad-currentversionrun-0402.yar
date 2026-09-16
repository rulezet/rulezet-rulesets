rule TTP_XOR_QUAD_CurrentVersionRun_0402 {
  strings:
    $key_0402 = { 57 6d [2] 73 63 [2] 58 4f [2] 76 6d [2] 62 76 [2] 6d 6c [2] 73 71 [2] 71 70 [2] 6a 76 [2] 76 71 [2] 6a 5e }

  condition:
    any of them
}