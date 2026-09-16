rule TTP_XOR_QUAD_CurrentVersionRun_cb11 {
  strings:
    $key_cb11 = { 98 7e [2] bc 70 [2] 97 5c [2] b9 7e [2] ad 65 [2] a2 7f [2] bc 62 [2] be 63 [2] a5 65 [2] b9 62 [2] a5 4d }

  condition:
    any of them
}