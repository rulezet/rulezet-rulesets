rule TTP_XOR_QUAD_CurrentVersionRun_bd2b {
  strings:
    $key_bd2b = { ee 44 [2] ca 4a [2] e1 66 [2] cf 44 [2] db 5f [2] d4 45 [2] ca 58 [2] c8 59 [2] d3 5f [2] cf 58 [2] d3 77 }

  condition:
    any of them
}