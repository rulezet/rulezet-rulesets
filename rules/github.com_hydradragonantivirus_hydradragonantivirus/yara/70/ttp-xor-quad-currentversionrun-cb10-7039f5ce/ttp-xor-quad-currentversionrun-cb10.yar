rule TTP_XOR_QUAD_CurrentVersionRun_cb10 {
  strings:
    $key_cb10 = { 98 7f [2] bc 71 [2] 97 5d [2] b9 7f [2] ad 64 [2] a2 7e [2] bc 63 [2] be 62 [2] a5 64 [2] b9 63 [2] a5 4c }

  condition:
    any of them
}