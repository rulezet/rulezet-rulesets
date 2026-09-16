rule TTP_XOR_QUAD_CurrentVersionRun_cb00 {
  strings:
    $key_cb00 = { 98 6f [2] bc 61 [2] 97 4d [2] b9 6f [2] ad 74 [2] a2 6e [2] bc 73 [2] be 72 [2] a5 74 [2] b9 73 [2] a5 5c }

  condition:
    any of them
}