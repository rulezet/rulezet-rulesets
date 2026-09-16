rule TTP_XOR_QUAD_CurrentVersionRun_bdff {
  strings:
    $key_bdff = { ee 90 [2] ca 9e [2] e1 b2 [2] cf 90 [2] db 8b [2] d4 91 [2] ca 8c [2] c8 8d [2] d3 8b [2] cf 8c [2] d3 a3 }

  condition:
    any of them
}