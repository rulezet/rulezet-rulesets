rule TTP_XOR_QUAD_CurrentVersionRun_bde2 {
  strings:
    $key_bde2 = { ee 8d [2] ca 83 [2] e1 af [2] cf 8d [2] db 96 [2] d4 8c [2] ca 91 [2] c8 90 [2] d3 96 [2] cf 91 [2] d3 be }

  condition:
    any of them
}