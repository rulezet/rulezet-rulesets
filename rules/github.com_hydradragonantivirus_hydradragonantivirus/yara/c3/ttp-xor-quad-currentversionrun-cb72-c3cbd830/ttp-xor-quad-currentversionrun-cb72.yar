rule TTP_XOR_QUAD_CurrentVersionRun_cb72 {
  strings:
    $key_cb72 = { 98 1d [2] bc 13 [2] 97 3f [2] b9 1d [2] ad 06 [2] a2 1c [2] bc 01 [2] be 00 [2] a5 06 [2] b9 01 [2] a5 2e }

  condition:
    any of them
}