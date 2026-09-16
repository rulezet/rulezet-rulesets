rule TTP_XOR_QUAD_CurrentVersionRun_bde4 {
  strings:
    $key_bde4 = { ee 8b [2] ca 85 [2] e1 a9 [2] cf 8b [2] db 90 [2] d4 8a [2] ca 97 [2] c8 96 [2] d3 90 [2] cf 97 [2] d3 b8 }

  condition:
    any of them
}