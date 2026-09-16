rule TTP_XOR_QUAD_CurrentVersionRun_7ecd {
  strings:
    $key_7ecd = { 2d a2 [2] 09 ac [2] 22 80 [2] 0c a2 [2] 18 b9 [2] 17 a3 [2] 09 be [2] 0b bf [2] 10 b9 [2] 0c be [2] 10 91 }

  condition:
    any of them
}