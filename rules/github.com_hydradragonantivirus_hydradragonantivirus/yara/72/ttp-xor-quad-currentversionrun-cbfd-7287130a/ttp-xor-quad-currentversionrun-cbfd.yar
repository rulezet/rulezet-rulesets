rule TTP_XOR_QUAD_CurrentVersionRun_cbfd {
  strings:
    $key_cbfd = { 98 92 [2] bc 9c [2] 97 b0 [2] b9 92 [2] ad 89 [2] a2 93 [2] bc 8e [2] be 8f [2] a5 89 [2] b9 8e [2] a5 a1 }

  condition:
    any of them
}