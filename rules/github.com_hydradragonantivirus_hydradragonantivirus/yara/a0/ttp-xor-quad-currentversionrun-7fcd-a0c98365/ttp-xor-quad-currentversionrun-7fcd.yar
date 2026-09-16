rule TTP_XOR_QUAD_CurrentVersionRun_7fcd {
  strings:
    $key_7fcd = { 2c a2 [2] 08 ac [2] 23 80 [2] 0d a2 [2] 19 b9 [2] 16 a3 [2] 08 be [2] 0a bf [2] 11 b9 [2] 0d be [2] 11 91 }

  condition:
    any of them
}