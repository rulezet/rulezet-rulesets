rule TTP_XOR_QUAD_CurrentVersionRun_cb54 {
  strings:
    $key_cb54 = { 98 3b [2] bc 35 [2] 97 19 [2] b9 3b [2] ad 20 [2] a2 3a [2] bc 27 [2] be 26 [2] a5 20 [2] b9 27 [2] a5 08 }

  condition:
    any of them
}