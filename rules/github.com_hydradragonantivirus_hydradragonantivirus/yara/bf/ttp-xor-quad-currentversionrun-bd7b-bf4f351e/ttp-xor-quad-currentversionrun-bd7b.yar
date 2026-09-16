rule TTP_XOR_QUAD_CurrentVersionRun_bd7b {
  strings:
    $key_bd7b = { ee 14 [2] ca 1a [2] e1 36 [2] cf 14 [2] db 0f [2] d4 15 [2] ca 08 [2] c8 09 [2] d3 0f [2] cf 08 [2] d3 27 }

  condition:
    any of them
}