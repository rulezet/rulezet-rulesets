rule TTP_XOR_QUAD_CurrentVersionRun_bd36 {
  strings:
    $key_bd36 = { ee 59 [2] ca 57 [2] e1 7b [2] cf 59 [2] db 42 [2] d4 58 [2] ca 45 [2] c8 44 [2] d3 42 [2] cf 45 [2] d3 6a }

  condition:
    any of them
}