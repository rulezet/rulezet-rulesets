rule TTP_XOR_QUAD_CurrentVersionRun_cb4c {
  strings:
    $key_cb4c = { 98 23 [2] bc 2d [2] 97 01 [2] b9 23 [2] ad 38 [2] a2 22 [2] bc 3f [2] be 3e [2] a5 38 [2] b9 3f [2] a5 10 }

  condition:
    any of them
}