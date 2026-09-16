rule TTP_XOR_QUAD_CurrentVersionRun_cb26 {
  strings:
    $key_cb26 = { 98 49 [2] bc 47 [2] 97 6b [2] b9 49 [2] ad 52 [2] a2 48 [2] bc 55 [2] be 54 [2] a5 52 [2] b9 55 [2] a5 7a }

  condition:
    any of them
}