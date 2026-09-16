rule TTP_XOR_QUAD_CurrentVersionRun_cb0b {
  strings:
    $key_cb0b = { 98 64 [2] bc 6a [2] 97 46 [2] b9 64 [2] ad 7f [2] a2 65 [2] bc 78 [2] be 79 [2] a5 7f [2] b9 78 [2] a5 57 }

  condition:
    any of them
}