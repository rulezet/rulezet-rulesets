rule TTP_XOR_QUAD_CurrentVersionRun_bdee {
  strings:
    $key_bdee = { ee 81 [2] ca 8f [2] e1 a3 [2] cf 81 [2] db 9a [2] d4 80 [2] ca 9d [2] c8 9c [2] d3 9a [2] cf 9d [2] d3 b2 }

  condition:
    any of them
}