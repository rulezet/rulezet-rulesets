rule TTP_XOR_QUAD_CurrentVersionRun_bd00 {
  strings:
    $key_bd00 = { ee 6f [2] ca 61 [2] e1 4d [2] cf 6f [2] db 74 [2] d4 6e [2] ca 73 [2] c8 72 [2] d3 74 [2] cf 73 [2] d3 5c }

  condition:
    any of them
}