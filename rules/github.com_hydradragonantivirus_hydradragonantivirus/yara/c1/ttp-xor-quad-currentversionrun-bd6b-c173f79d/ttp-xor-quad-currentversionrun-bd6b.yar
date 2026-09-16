rule TTP_XOR_QUAD_CurrentVersionRun_bd6b {
  strings:
    $key_bd6b = { ee 04 [2] ca 0a [2] e1 26 [2] cf 04 [2] db 1f [2] d4 05 [2] ca 18 [2] c8 19 [2] d3 1f [2] cf 18 [2] d3 37 }

  condition:
    any of them
}