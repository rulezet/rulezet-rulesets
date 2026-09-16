rule TTP_XOR_QUAD_CurrentVersionRun_cb5c {
  strings:
    $key_cb5c = { 98 33 [2] bc 3d [2] 97 11 [2] b9 33 [2] ad 28 [2] a2 32 [2] bc 2f [2] be 2e [2] a5 28 [2] b9 2f [2] a5 00 }

  condition:
    any of them
}