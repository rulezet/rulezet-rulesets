rule TTP_XOR_QUAD_CurrentVersionRun_bd5a {
  strings:
    $key_bd5a = { ee 35 [2] ca 3b [2] e1 17 [2] cf 35 [2] db 2e [2] d4 34 [2] ca 29 [2] c8 28 [2] d3 2e [2] cf 29 [2] d3 06 }

  condition:
    any of them
}