rule TTP_XOR_QUAD_CurrentVersionRun_4ecd {
  strings:
    $key_4ecd = { 1d a2 [2] 39 ac [2] 12 80 [2] 3c a2 [2] 28 b9 [2] 27 a3 [2] 39 be [2] 3b bf [2] 20 b9 [2] 3c be [2] 20 91 }

  condition:
    any of them
}