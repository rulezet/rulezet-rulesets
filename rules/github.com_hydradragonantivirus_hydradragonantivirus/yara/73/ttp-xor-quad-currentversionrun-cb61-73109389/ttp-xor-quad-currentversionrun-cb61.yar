rule TTP_XOR_QUAD_CurrentVersionRun_cb61 {
  strings:
    $key_cb61 = { 98 0e [2] bc 00 [2] 97 2c [2] b9 0e [2] ad 15 [2] a2 0f [2] bc 12 [2] be 13 [2] a5 15 [2] b9 12 [2] a5 3d }

  condition:
    any of them
}