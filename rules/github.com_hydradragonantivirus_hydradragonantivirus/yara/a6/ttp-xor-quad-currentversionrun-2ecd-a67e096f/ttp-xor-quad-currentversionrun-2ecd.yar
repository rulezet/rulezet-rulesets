rule TTP_XOR_QUAD_CurrentVersionRun_2ecd {
  strings:
    $key_2ecd = { 7d a2 [2] 59 ac [2] 72 80 [2] 5c a2 [2] 48 b9 [2] 47 a3 [2] 59 be [2] 5b bf [2] 40 b9 [2] 5c be [2] 40 91 }

  condition:
    any of them
}