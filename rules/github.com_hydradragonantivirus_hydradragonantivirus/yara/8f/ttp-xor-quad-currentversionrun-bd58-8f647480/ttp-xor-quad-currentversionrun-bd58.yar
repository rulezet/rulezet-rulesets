rule TTP_XOR_QUAD_CurrentVersionRun_bd58 {
  strings:
    $key_bd58 = { ee 37 [2] ca 39 [2] e1 15 [2] cf 37 [2] db 2c [2] d4 36 [2] ca 2b [2] c8 2a [2] d3 2c [2] cf 2b [2] d3 04 }

  condition:
    any of them
}