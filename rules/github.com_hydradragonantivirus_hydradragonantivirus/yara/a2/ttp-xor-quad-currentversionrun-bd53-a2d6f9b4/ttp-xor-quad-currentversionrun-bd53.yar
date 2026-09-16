rule TTP_XOR_QUAD_CurrentVersionRun_bd53 {
  strings:
    $key_bd53 = { ee 3c [2] ca 32 [2] e1 1e [2] cf 3c [2] db 27 [2] d4 3d [2] ca 20 [2] c8 21 [2] d3 27 [2] cf 20 [2] d3 0f }

  condition:
    any of them
}