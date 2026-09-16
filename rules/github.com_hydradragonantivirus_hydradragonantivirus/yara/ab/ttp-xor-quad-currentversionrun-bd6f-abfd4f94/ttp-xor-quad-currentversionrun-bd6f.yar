rule TTP_XOR_QUAD_CurrentVersionRun_bd6f {
  strings:
    $key_bd6f = { ee 00 [2] ca 0e [2] e1 22 [2] cf 00 [2] db 1b [2] d4 01 [2] ca 1c [2] c8 1d [2] d3 1b [2] cf 1c [2] d3 33 }

  condition:
    any of them
}