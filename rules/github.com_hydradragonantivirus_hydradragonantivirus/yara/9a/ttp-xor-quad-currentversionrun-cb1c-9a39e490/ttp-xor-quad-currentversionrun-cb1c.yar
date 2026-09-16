rule TTP_XOR_QUAD_CurrentVersionRun_cb1c {
  strings:
    $key_cb1c = { 98 73 [2] bc 7d [2] 97 51 [2] b9 73 [2] ad 68 [2] a2 72 [2] bc 6f [2] be 6e [2] a5 68 [2] b9 6f [2] a5 40 }

  condition:
    any of them
}