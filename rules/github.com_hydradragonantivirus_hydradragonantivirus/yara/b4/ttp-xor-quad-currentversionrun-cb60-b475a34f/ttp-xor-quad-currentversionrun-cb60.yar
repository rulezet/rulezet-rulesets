rule TTP_XOR_QUAD_CurrentVersionRun_cb60 {
  strings:
    $key_cb60 = { 98 0f [2] bc 01 [2] 97 2d [2] b9 0f [2] ad 14 [2] a2 0e [2] bc 13 [2] be 12 [2] a5 14 [2] b9 13 [2] a5 3c }

  condition:
    any of them
}