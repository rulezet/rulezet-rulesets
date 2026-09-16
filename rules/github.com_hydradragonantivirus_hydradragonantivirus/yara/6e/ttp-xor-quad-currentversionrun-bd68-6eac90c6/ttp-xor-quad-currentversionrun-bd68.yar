rule TTP_XOR_QUAD_CurrentVersionRun_bd68 {
  strings:
    $key_bd68 = { ee 07 [2] ca 09 [2] e1 25 [2] cf 07 [2] db 1c [2] d4 06 [2] ca 1b [2] c8 1a [2] d3 1c [2] cf 1b [2] d3 34 }

  condition:
    any of them
}