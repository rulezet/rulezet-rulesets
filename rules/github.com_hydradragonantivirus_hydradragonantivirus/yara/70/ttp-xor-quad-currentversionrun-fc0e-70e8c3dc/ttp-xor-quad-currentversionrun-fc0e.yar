rule TTP_XOR_QUAD_CurrentVersionRun_fc0e {
  strings:
    $key_fc0e = { af 61 [2] 8b 6f [2] a0 43 [2] 8e 61 [2] 9a 7a [2] 95 60 [2] 8b 7d [2] 89 7c [2] 92 7a [2] 8e 7d [2] 92 52 }

  condition:
    any of them
}