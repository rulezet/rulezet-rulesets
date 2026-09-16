rule TTP_XOR_QUAD_CurrentVersionRun_bd5d {
  strings:
    $key_bd5d = { ee 32 [2] ca 3c [2] e1 10 [2] cf 32 [2] db 29 [2] d4 33 [2] ca 2e [2] c8 2f [2] d3 29 [2] cf 2e [2] d3 01 }

  condition:
    any of them
}