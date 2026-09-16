rule TTP_XOR_QUAD_CurrentVersionRun_cb3b {
  strings:
    $key_cb3b = { 98 54 [2] bc 5a [2] 97 76 [2] b9 54 [2] ad 4f [2] a2 55 [2] bc 48 [2] be 49 [2] a5 4f [2] b9 48 [2] a5 67 }

  condition:
    any of them
}