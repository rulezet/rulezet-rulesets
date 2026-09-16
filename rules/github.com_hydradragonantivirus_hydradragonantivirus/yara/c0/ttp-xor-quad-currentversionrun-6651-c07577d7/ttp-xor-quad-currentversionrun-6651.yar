rule TTP_XOR_QUAD_CurrentVersionRun_6651 {
  strings:
    $key_6651 = { 35 3e [2] 11 30 [2] 3a 1c [2] 14 3e [2] 00 25 [2] 0f 3f [2] 11 22 [2] 13 23 [2] 08 25 [2] 14 22 [2] 08 0d }

  condition:
    any of them
}