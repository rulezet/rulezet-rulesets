rule TTP_XOR_QUAD_CurrentVersionRun_57d1 {
  strings:
    $key_57d1 = { 04 be [2] 20 b0 [2] 0b 9c [2] 25 be [2] 31 a5 [2] 3e bf [2] 20 a2 [2] 22 a3 [2] 39 a5 [2] 25 a2 [2] 39 8d }

  condition:
    any of them
}