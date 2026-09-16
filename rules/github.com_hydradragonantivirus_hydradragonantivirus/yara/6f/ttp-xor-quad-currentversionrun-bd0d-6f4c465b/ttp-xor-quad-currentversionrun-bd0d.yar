rule TTP_XOR_QUAD_CurrentVersionRun_bd0d {
  strings:
    $key_bd0d = { ee 62 [2] ca 6c [2] e1 40 [2] cf 62 [2] db 79 [2] d4 63 [2] ca 7e [2] c8 7f [2] d3 79 [2] cf 7e [2] d3 51 }

  condition:
    any of them
}