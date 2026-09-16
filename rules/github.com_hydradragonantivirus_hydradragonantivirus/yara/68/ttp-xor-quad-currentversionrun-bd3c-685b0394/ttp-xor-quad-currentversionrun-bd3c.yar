rule TTP_XOR_QUAD_CurrentVersionRun_bd3c {
  strings:
    $key_bd3c = { ee 53 [2] ca 5d [2] e1 71 [2] cf 53 [2] db 48 [2] d4 52 [2] ca 4f [2] c8 4e [2] d3 48 [2] cf 4f [2] d3 60 }

  condition:
    any of them
}