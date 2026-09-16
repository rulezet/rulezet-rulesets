rule TTP_XOR_QUAD_CurrentVersionRun_cb40 {
  strings:
    $key_cb40 = { 98 2f [2] bc 21 [2] 97 0d [2] b9 2f [2] ad 34 [2] a2 2e [2] bc 33 [2] be 32 [2] a5 34 [2] b9 33 [2] a5 1c }

  condition:
    any of them
}