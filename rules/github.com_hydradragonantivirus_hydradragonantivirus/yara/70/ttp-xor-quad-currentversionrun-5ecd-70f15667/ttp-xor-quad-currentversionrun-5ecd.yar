rule TTP_XOR_QUAD_CurrentVersionRun_5ecd {
  strings:
    $key_5ecd = { 0d a2 [2] 29 ac [2] 02 80 [2] 2c a2 [2] 38 b9 [2] 37 a3 [2] 29 be [2] 2b bf [2] 30 b9 [2] 2c be [2] 30 91 }

  condition:
    any of them
}