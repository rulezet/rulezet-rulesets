rule TTP_XOR_QUAD_CurrentVersionRun_cb59 {
  strings:
    $key_cb59 = { 98 36 [2] bc 38 [2] 97 14 [2] b9 36 [2] ad 2d [2] a2 37 [2] bc 2a [2] be 2b [2] a5 2d [2] b9 2a [2] a5 05 }

  condition:
    any of them
}