rule TTP_XOR_QUAD_CurrentVersionRun_bd02 {
  strings:
    $key_bd02 = { ee 6d [2] ca 63 [2] e1 4f [2] cf 6d [2] db 76 [2] d4 6c [2] ca 71 [2] c8 70 [2] d3 76 [2] cf 71 [2] d3 5e }

  condition:
    any of them
}