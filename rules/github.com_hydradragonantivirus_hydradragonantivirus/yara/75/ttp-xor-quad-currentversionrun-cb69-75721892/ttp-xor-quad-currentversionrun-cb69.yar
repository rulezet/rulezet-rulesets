rule TTP_XOR_QUAD_CurrentVersionRun_cb69 {
  strings:
    $key_cb69 = { 98 06 [2] bc 08 [2] 97 24 [2] b9 06 [2] ad 1d [2] a2 07 [2] bc 1a [2] be 1b [2] a5 1d [2] b9 1a [2] a5 35 }

  condition:
    any of them
}