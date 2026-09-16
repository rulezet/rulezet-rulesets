rule TTP_XOR_QUAD_CurrentVersionRun_32d1 {
  strings:
    $key_32d1 = { 61 be [2] 45 b0 [2] 6e 9c [2] 40 be [2] 54 a5 [2] 5b bf [2] 45 a2 [2] 47 a3 [2] 5c a5 [2] 40 a2 [2] 5c 8d }

  condition:
    any of them
}