rule TTP_XOR_QUAD_CurrentVersionRun_cb65 {
  strings:
    $key_cb65 = { 98 0a [2] bc 04 [2] 97 28 [2] b9 0a [2] ad 11 [2] a2 0b [2] bc 16 [2] be 17 [2] a5 11 [2] b9 16 [2] a5 39 }

  condition:
    any of them
}