rule TTP_XOR_QUAD_CurrentVersionRun_bd48 {
  strings:
    $key_bd48 = { ee 27 [2] ca 29 [2] e1 05 [2] cf 27 [2] db 3c [2] d4 26 [2] ca 3b [2] c8 3a [2] d3 3c [2] cf 3b [2] d3 14 }

  condition:
    any of them
}