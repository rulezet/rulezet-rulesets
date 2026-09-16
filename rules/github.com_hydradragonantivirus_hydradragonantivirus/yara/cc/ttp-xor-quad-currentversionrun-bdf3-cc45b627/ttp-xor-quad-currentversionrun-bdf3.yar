rule TTP_XOR_QUAD_CurrentVersionRun_bdf3 {
  strings:
    $key_bdf3 = { ee 9c [2] ca 92 [2] e1 be [2] cf 9c [2] db 87 [2] d4 9d [2] ca 80 [2] c8 81 [2] d3 87 [2] cf 80 [2] d3 af }

  condition:
    any of them
}