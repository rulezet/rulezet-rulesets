rule TTP_XOR_QUAD_CurrentVersionRun_bd67 {
  strings:
    $key_bd67 = { ee 08 [2] ca 06 [2] e1 2a [2] cf 08 [2] db 13 [2] d4 09 [2] ca 14 [2] c8 15 [2] d3 13 [2] cf 14 [2] d3 3b }

  condition:
    any of them
}