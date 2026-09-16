rule TTP_XOR_QUAD_CurrentVersionRun_1602 {
  strings:
    $key_1602 = { 45 6d [2] 61 63 [2] 4a 4f [2] 64 6d [2] 70 76 [2] 7f 6c [2] 61 71 [2] 63 70 [2] 78 76 [2] 64 71 [2] 78 5e }

  condition:
    any of them
}