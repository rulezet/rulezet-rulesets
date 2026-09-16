rule TTP_XOR_QUAD_CurrentVersionRun_3fcd {
  strings:
    $key_3fcd = { 6c a2 [2] 48 ac [2] 63 80 [2] 4d a2 [2] 59 b9 [2] 56 a3 [2] 48 be [2] 4a bf [2] 51 b9 [2] 4d be [2] 51 91 }

  condition:
    any of them
}