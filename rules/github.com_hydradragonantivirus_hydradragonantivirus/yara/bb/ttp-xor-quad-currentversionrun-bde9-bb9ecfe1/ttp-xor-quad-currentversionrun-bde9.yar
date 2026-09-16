rule TTP_XOR_QUAD_CurrentVersionRun_bde9 {
  strings:
    $key_bde9 = { ee 86 [2] ca 88 [2] e1 a4 [2] cf 86 [2] db 9d [2] d4 87 [2] ca 9a [2] c8 9b [2] d3 9d [2] cf 9a [2] d3 b5 }

  condition:
    any of them
}