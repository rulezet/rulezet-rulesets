rule TTP_XOR_QUAD_CurrentVersionRun_bde8 {
  strings:
    $key_bde8 = { ee 87 [2] ca 89 [2] e1 a5 [2] cf 87 [2] db 9c [2] d4 86 [2] ca 9b [2] c8 9a [2] d3 9c [2] cf 9b [2] d3 b4 }

  condition:
    any of them
}