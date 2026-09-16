rule TTP_XOR_QUAD_CurrentVersionRun_bdfe {
  strings:
    $key_bdfe = { ee 91 [2] ca 9f [2] e1 b3 [2] cf 91 [2] db 8a [2] d4 90 [2] ca 8d [2] c8 8c [2] d3 8a [2] cf 8d [2] d3 a2 }

  condition:
    any of them
}