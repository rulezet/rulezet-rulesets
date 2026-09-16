rule TTP_XOR_QUAD_CurrentVersionRun_cb55 {
  strings:
    $key_cb55 = { 98 3a [2] bc 34 [2] 97 18 [2] b9 3a [2] ad 21 [2] a2 3b [2] bc 26 [2] be 27 [2] a5 21 [2] b9 26 [2] a5 09 }

  condition:
    any of them
}