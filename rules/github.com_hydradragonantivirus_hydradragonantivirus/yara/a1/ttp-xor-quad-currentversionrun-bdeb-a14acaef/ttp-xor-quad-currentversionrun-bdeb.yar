rule TTP_XOR_QUAD_CurrentVersionRun_bdeb {
  strings:
    $key_bdeb = { ee 84 [2] ca 8a [2] e1 a6 [2] cf 84 [2] db 9f [2] d4 85 [2] ca 98 [2] c8 99 [2] d3 9f [2] cf 98 [2] d3 b7 }

  condition:
    any of them
}