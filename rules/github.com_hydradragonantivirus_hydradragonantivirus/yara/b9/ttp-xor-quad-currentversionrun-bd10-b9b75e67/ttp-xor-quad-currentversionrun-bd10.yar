rule TTP_XOR_QUAD_CurrentVersionRun_bd10 {
  strings:
    $key_bd10 = { ee 7f [2] ca 71 [2] e1 5d [2] cf 7f [2] db 64 [2] d4 7e [2] ca 63 [2] c8 62 [2] d3 64 [2] cf 63 [2] d3 4c }

  condition:
    any of them
}