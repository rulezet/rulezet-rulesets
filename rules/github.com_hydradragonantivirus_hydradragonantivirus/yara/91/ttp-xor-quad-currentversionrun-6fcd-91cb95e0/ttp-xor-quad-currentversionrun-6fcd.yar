rule TTP_XOR_QUAD_CurrentVersionRun_6fcd {
  strings:
    $key_6fcd = { 3c a2 [2] 18 ac [2] 33 80 [2] 1d a2 [2] 09 b9 [2] 06 a3 [2] 18 be [2] 1a bf [2] 01 b9 [2] 1d be [2] 01 91 }

  condition:
    any of them
}