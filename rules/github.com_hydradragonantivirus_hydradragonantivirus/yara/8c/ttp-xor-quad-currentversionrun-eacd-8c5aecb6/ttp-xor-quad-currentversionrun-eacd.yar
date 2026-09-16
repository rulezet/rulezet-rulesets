rule TTP_XOR_QUAD_CurrentVersionRun_eacd {
  strings:
    $key_eacd = { b9 a2 [2] 9d ac [2] b6 80 [2] 98 a2 [2] 8c b9 [2] 83 a3 [2] 9d be [2] 9f bf [2] 84 b9 [2] 98 be [2] 84 91 }

  condition:
    any of them
}