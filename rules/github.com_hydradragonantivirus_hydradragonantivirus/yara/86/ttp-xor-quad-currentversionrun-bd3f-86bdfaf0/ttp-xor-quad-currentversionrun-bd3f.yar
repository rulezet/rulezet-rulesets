rule TTP_XOR_QUAD_CurrentVersionRun_bd3f {
  strings:
    $key_bd3f = { ee 50 [2] ca 5e [2] e1 72 [2] cf 50 [2] db 4b [2] d4 51 [2] ca 4c [2] c8 4d [2] d3 4b [2] cf 4c [2] d3 63 }

  condition:
    any of them
}