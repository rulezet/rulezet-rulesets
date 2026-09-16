rule TTP_XOR_QUAD_CurrentVersionRun_bd38 {
  strings:
    $key_bd38 = { ee 57 [2] ca 59 [2] e1 75 [2] cf 57 [2] db 4c [2] d4 56 [2] ca 4b [2] c8 4a [2] d3 4c [2] cf 4b [2] d3 64 }

  condition:
    any of them
}