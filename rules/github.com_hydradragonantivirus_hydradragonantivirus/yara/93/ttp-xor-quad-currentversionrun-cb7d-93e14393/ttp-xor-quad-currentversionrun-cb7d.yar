rule TTP_XOR_QUAD_CurrentVersionRun_cb7d {
  strings:
    $key_cb7d = { 98 12 [2] bc 1c [2] 97 30 [2] b9 12 [2] ad 09 [2] a2 13 [2] bc 0e [2] be 0f [2] a5 09 [2] b9 0e [2] a5 21 }

  condition:
    any of them
}