rule TTP_XOR_QUAD_CurrentVersionRun_cb4a {
  strings:
    $key_cb4a = { 98 25 [2] bc 2b [2] 97 07 [2] b9 25 [2] ad 3e [2] a2 24 [2] bc 39 [2] be 38 [2] a5 3e [2] b9 39 [2] a5 16 }

  condition:
    any of them
}