rule TTP_XOR_QUAD_CurrentVersionRun_bd7c {
  strings:
    $key_bd7c = { ee 13 [2] ca 1d [2] e1 31 [2] cf 13 [2] db 08 [2] d4 12 [2] ca 0f [2] c8 0e [2] d3 08 [2] cf 0f [2] d3 20 }

  condition:
    any of them
}