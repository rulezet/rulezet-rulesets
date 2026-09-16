rule TTP_XOR_QUAD_CurrentVersionRun_cb6b {
  strings:
    $key_cb6b = { 98 04 [2] bc 0a [2] 97 26 [2] b9 04 [2] ad 1f [2] a2 05 [2] bc 18 [2] be 19 [2] a5 1f [2] b9 18 [2] a5 37 }

  condition:
    any of them
}