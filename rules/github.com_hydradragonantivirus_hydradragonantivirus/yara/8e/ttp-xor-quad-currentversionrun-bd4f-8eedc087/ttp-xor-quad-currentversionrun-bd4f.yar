rule TTP_XOR_QUAD_CurrentVersionRun_bd4f {
  strings:
    $key_bd4f = { ee 20 [2] ca 2e [2] e1 02 [2] cf 20 [2] db 3b [2] d4 21 [2] ca 3c [2] c8 3d [2] d3 3b [2] cf 3c [2] d3 13 }

  condition:
    any of them
}