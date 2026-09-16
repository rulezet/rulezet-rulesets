rule TTP_XOR_QUAD_CurrentVersionRun_bd28 {
  strings:
    $key_bd28 = { ee 47 [2] ca 49 [2] e1 65 [2] cf 47 [2] db 5c [2] d4 46 [2] ca 5b [2] c8 5a [2] d3 5c [2] cf 5b [2] d3 74 }

  condition:
    any of them
}