rule TTP_XOR_QUAD_CurrentVersionRun_bde3 {
  strings:
    $key_bde3 = { ee 8c [2] ca 82 [2] e1 ae [2] cf 8c [2] db 97 [2] d4 8d [2] ca 90 [2] c8 91 [2] d3 97 [2] cf 90 [2] d3 bf }

  condition:
    any of them
}