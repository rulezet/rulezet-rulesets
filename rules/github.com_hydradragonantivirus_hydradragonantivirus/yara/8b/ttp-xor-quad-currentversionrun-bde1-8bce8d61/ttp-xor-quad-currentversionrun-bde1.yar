rule TTP_XOR_QUAD_CurrentVersionRun_bde1 {
  strings:
    $key_bde1 = { ee 8e [2] ca 80 [2] e1 ac [2] cf 8e [2] db 95 [2] d4 8f [2] ca 92 [2] c8 93 [2] d3 95 [2] cf 92 [2] d3 bd }

  condition:
    any of them
}