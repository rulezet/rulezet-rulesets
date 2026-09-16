rule TTP_XOR_QUAD_CurrentVersionRun_bd7e {
  strings:
    $key_bd7e = { ee 11 [2] ca 1f [2] e1 33 [2] cf 11 [2] db 0a [2] d4 10 [2] ca 0d [2] c8 0c [2] d3 0a [2] cf 0d [2] d3 22 }

  condition:
    any of them
}