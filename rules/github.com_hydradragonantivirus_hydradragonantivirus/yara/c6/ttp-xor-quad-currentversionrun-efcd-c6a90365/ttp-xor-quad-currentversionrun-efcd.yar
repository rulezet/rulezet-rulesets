rule TTP_XOR_QUAD_CurrentVersionRun_efcd {
  strings:
    $key_efcd = { bc a2 [2] 98 ac [2] b3 80 [2] 9d a2 [2] 89 b9 [2] 86 a3 [2] 98 be [2] 9a bf [2] 81 b9 [2] 9d be [2] 81 91 }

  condition:
    any of them
}