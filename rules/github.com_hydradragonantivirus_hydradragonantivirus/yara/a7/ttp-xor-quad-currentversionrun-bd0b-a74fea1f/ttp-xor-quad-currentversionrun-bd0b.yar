rule TTP_XOR_QUAD_CurrentVersionRun_bd0b {
  strings:
    $key_bd0b = { ee 64 [2] ca 6a [2] e1 46 [2] cf 64 [2] db 7f [2] d4 65 [2] ca 78 [2] c8 79 [2] d3 7f [2] cf 78 [2] d3 57 }

  condition:
    any of them
}