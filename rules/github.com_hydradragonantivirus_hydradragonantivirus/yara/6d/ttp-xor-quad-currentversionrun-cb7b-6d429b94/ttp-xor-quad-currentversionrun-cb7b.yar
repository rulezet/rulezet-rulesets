rule TTP_XOR_QUAD_CurrentVersionRun_cb7b {
  strings:
    $key_cb7b = { 98 14 [2] bc 1a [2] 97 36 [2] b9 14 [2] ad 0f [2] a2 15 [2] bc 08 [2] be 09 [2] a5 0f [2] b9 08 [2] a5 27 }

  condition:
    any of them
}