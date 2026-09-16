rule TTP_XOR_QUAD_CurrentVersionRun_bdec {
  strings:
    $key_bdec = { ee 83 [2] ca 8d [2] e1 a1 [2] cf 83 [2] db 98 [2] d4 82 [2] ca 9f [2] c8 9e [2] d3 98 [2] cf 9f [2] d3 b0 }

  condition:
    any of them
}