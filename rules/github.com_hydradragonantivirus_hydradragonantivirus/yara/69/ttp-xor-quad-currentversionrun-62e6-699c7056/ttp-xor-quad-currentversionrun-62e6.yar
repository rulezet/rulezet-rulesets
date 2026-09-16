rule TTP_XOR_QUAD_CurrentVersionRun_62e6 {
  strings:
    $key_62e6 = { 31 89 [2] 15 87 [2] 3e ab [2] 10 89 [2] 04 92 [2] 0b 88 [2] 15 95 [2] 17 94 [2] 0c 92 [2] 10 95 [2] 0c ba }

  condition:
    any of them
}