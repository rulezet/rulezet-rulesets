rule TTP_XOR_QUAD_CurrentVersionRun_bd56 {
  strings:
    $key_bd56 = { ee 39 [2] ca 37 [2] e1 1b [2] cf 39 [2] db 22 [2] d4 38 [2] ca 25 [2] c8 24 [2] d3 22 [2] cf 25 [2] d3 0a }

  condition:
    any of them
}