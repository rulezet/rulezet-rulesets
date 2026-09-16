rule TTP_XOR_QUAD_CurrentVersionRun_bde5 {
  strings:
    $key_bde5 = { ee 8a [2] ca 84 [2] e1 a8 [2] cf 8a [2] db 91 [2] d4 8b [2] ca 96 [2] c8 97 [2] d3 91 [2] cf 96 [2] d3 b9 }

  condition:
    any of them
}