rule TTP_XOR_QUAD_CurrentVersionRun_cb2b {
  strings:
    $key_cb2b = { 98 44 [2] bc 4a [2] 97 66 [2] b9 44 [2] ad 5f [2] a2 45 [2] bc 58 [2] be 59 [2] a5 5f [2] b9 58 [2] a5 77 }

  condition:
    any of them
}