rule TTP_XOR_QUAD_CurrentVersionRun_bd0a {
  strings:
    $key_bd0a = { ee 65 [2] ca 6b [2] e1 47 [2] cf 65 [2] db 7e [2] d4 64 [2] ca 79 [2] c8 78 [2] d3 7e [2] cf 79 [2] d3 56 }

  condition:
    any of them
}