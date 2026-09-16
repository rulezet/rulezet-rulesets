rule TTP_XOR_QUAD_CurrentVersionRun_cb13 {
  strings:
    $key_cb13 = { 98 7c [2] bc 72 [2] 97 5e [2] b9 7c [2] ad 67 [2] a2 7d [2] bc 60 [2] be 61 [2] a5 67 [2] b9 60 [2] a5 4f }

  condition:
    any of them
}