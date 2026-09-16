rule TTP_XOR_QUAD_CurrentVersionRun_62d1 {
  strings:
    $key_62d1 = { 31 be [2] 15 b0 [2] 3e 9c [2] 10 be [2] 04 a5 [2] 0b bf [2] 15 a2 [2] 17 a3 [2] 0c a5 [2] 10 a2 [2] 0c 8d }

  condition:
    any of them
}