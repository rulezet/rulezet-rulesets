rule TTP_XOR_QUAD_CurrentVersionRun_fc14 {
  strings:
    $key_fc14 = { af 7b [2] 8b 75 [2] a0 59 [2] 8e 7b [2] 9a 60 [2] 95 7a [2] 8b 67 [2] 89 66 [2] 92 60 [2] 8e 67 [2] 92 48 }

  condition:
    any of them
}