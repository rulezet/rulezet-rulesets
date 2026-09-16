rule TTP_XOR_QUAD_CurrentVersionRun_6ecd {
  strings:
    $key_6ecd = { 3d a2 [2] 19 ac [2] 32 80 [2] 1c a2 [2] 08 b9 [2] 07 a3 [2] 19 be [2] 1b bf [2] 00 b9 [2] 1c be [2] 00 91 }

  condition:
    any of them
}