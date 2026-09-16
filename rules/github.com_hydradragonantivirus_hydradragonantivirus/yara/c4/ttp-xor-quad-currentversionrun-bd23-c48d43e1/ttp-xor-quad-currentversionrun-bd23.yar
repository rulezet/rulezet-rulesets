rule TTP_XOR_QUAD_CurrentVersionRun_bd23 {
  strings:
    $key_bd23 = { ee 4c [2] ca 42 [2] e1 6e [2] cf 4c [2] db 57 [2] d4 4d [2] ca 50 [2] c8 51 [2] d3 57 [2] cf 50 [2] d3 7f }

  condition:
    any of them
}