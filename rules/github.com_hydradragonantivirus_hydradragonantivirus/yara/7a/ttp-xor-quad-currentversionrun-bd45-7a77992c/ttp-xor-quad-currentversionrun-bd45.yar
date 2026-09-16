rule TTP_XOR_QUAD_CurrentVersionRun_bd45 {
  strings:
    $key_bd45 = { ee 2a [2] ca 24 [2] e1 08 [2] cf 2a [2] db 31 [2] d4 2b [2] ca 36 [2] c8 37 [2] d3 31 [2] cf 36 [2] d3 19 }

  condition:
    any of them
}