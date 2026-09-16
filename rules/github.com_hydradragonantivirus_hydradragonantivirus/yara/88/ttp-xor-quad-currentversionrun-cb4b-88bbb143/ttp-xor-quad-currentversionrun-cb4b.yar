rule TTP_XOR_QUAD_CurrentVersionRun_cb4b {
  strings:
    $key_cb4b = { 98 24 [2] bc 2a [2] 97 06 [2] b9 24 [2] ad 3f [2] a2 25 [2] bc 38 [2] be 39 [2] a5 3f [2] b9 38 [2] a5 17 }

  condition:
    any of them
}