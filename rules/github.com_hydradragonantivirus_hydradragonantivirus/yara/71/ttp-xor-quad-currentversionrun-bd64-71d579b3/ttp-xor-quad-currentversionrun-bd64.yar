rule TTP_XOR_QUAD_CurrentVersionRun_bd64 {
  strings:
    $key_bd64 = { ee 0b [2] ca 05 [2] e1 29 [2] cf 0b [2] db 10 [2] d4 0a [2] ca 17 [2] c8 16 [2] d3 10 [2] cf 17 [2] d3 38 }

  condition:
    any of them
}