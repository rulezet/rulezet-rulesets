rule TTP_XOR_QUAD_CurrentVersionRun_0102 {
  strings:
    $key_0102 = { 52 6d [2] 76 63 [2] 5d 4f [2] 73 6d [2] 67 76 [2] 68 6c [2] 76 71 [2] 74 70 [2] 6f 76 [2] 73 71 [2] 6f 5e }

  condition:
    any of them
}