rule TTP_XOR_QUAD_CurrentVersionRun_bd3e {
  strings:
    $key_bd3e = { ee 51 [2] ca 5f [2] e1 73 [2] cf 51 [2] db 4a [2] d4 50 [2] ca 4d [2] c8 4c [2] d3 4a [2] cf 4d [2] d3 62 }

  condition:
    any of them
}