rule TTP_XOR_QUAD_CurrentVersionRun_cb2c {
  strings:
    $key_cb2c = { 98 43 [2] bc 4d [2] 97 61 [2] b9 43 [2] ad 58 [2] a2 42 [2] bc 5f [2] be 5e [2] a5 58 [2] b9 5f [2] a5 70 }

  condition:
    any of them
}