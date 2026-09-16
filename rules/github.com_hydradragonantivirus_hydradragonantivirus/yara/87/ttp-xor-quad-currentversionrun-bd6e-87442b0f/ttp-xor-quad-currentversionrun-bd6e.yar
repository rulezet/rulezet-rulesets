rule TTP_XOR_QUAD_CurrentVersionRun_bd6e {
  strings:
    $key_bd6e = { ee 01 [2] ca 0f [2] e1 23 [2] cf 01 [2] db 1a [2] d4 00 [2] ca 1d [2] c8 1c [2] d3 1a [2] cf 1d [2] d3 32 }

  condition:
    any of them
}