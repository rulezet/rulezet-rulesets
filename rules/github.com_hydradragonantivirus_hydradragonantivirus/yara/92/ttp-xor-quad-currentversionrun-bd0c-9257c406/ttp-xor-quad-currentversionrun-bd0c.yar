rule TTP_XOR_QUAD_CurrentVersionRun_bd0c {
  strings:
    $key_bd0c = { ee 63 [2] ca 6d [2] e1 41 [2] cf 63 [2] db 78 [2] d4 62 [2] ca 7f [2] c8 7e [2] d3 78 [2] cf 7f [2] d3 50 }

  condition:
    any of them
}