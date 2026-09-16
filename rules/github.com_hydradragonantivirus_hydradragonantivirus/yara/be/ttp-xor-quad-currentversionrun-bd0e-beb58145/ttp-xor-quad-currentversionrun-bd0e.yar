rule TTP_XOR_QUAD_CurrentVersionRun_bd0e {
  strings:
    $key_bd0e = { ee 61 [2] ca 6f [2] e1 43 [2] cf 61 [2] db 7a [2] d4 60 [2] ca 7d [2] c8 7c [2] d3 7a [2] cf 7d [2] d3 52 }

  condition:
    any of them
}