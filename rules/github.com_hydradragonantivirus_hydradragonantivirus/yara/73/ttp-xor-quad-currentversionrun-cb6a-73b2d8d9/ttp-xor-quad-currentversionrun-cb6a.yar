rule TTP_XOR_QUAD_CurrentVersionRun_cb6a {
  strings:
    $key_cb6a = { 98 05 [2] bc 0b [2] 97 27 [2] b9 05 [2] ad 1e [2] a2 04 [2] bc 19 [2] be 18 [2] a5 1e [2] b9 19 [2] a5 36 }

  condition:
    any of them
}