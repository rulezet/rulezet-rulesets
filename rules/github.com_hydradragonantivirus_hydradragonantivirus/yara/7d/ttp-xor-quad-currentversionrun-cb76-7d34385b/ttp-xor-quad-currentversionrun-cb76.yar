rule TTP_XOR_QUAD_CurrentVersionRun_cb76 {
  strings:
    $key_cb76 = { 98 19 [2] bc 17 [2] 97 3b [2] b9 19 [2] ad 02 [2] a2 18 [2] bc 05 [2] be 04 [2] a5 02 [2] b9 05 [2] a5 2a }

  condition:
    any of them
}