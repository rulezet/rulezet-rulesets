rule TTP_XOR_QUAD_CurrentVersionRun_bd18 {
  strings:
    $key_bd18 = { ee 77 [2] ca 79 [2] e1 55 [2] cf 77 [2] db 6c [2] d4 76 [2] ca 6b [2] c8 6a [2] d3 6c [2] cf 6b [2] d3 44 }

  condition:
    any of them
}