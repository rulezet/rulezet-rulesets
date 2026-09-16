rule TTP_XOR_QUAD_CurrentVersionRun_12d1 {
  strings:
    $key_12d1 = { 41 be [2] 65 b0 [2] 4e 9c [2] 60 be [2] 74 a5 [2] 7b bf [2] 65 a2 [2] 67 a3 [2] 7c a5 [2] 60 a2 [2] 7c 8d }

  condition:
    any of them
}