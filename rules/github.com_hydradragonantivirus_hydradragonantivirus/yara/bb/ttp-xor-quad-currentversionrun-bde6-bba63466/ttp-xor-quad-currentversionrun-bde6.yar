rule TTP_XOR_QUAD_CurrentVersionRun_bde6 {
  strings:
    $key_bde6 = { ee 89 [2] ca 87 [2] e1 ab [2] cf 89 [2] db 92 [2] d4 88 [2] ca 95 [2] c8 94 [2] d3 92 [2] cf 95 [2] d3 ba }

  condition:
    any of them
}