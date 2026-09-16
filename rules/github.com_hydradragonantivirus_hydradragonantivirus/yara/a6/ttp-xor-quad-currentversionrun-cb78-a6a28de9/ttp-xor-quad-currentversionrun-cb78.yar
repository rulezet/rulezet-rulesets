rule TTP_XOR_QUAD_CurrentVersionRun_cb78 {
  strings:
    $key_cb78 = { 98 17 [2] bc 19 [2] 97 35 [2] b9 17 [2] ad 0c [2] a2 16 [2] bc 0b [2] be 0a [2] a5 0c [2] b9 0b [2] a5 24 }

  condition:
    any of them
}