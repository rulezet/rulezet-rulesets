rule TTP_XOR_QUAD_CurrentVersionRun_cb07 {
  strings:
    $key_cb07 = { 98 68 [2] bc 66 [2] 97 4a [2] b9 68 [2] ad 73 [2] a2 69 [2] bc 74 [2] be 75 [2] a5 73 [2] b9 74 [2] a5 5b }

  condition:
    any of them
}