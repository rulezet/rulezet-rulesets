rule TTP_XOR_QUAD_CurrentVersionRun_cb50 {
  strings:
    $key_cb50 = { 98 3f [2] bc 31 [2] 97 1d [2] b9 3f [2] ad 24 [2] a2 3e [2] bc 23 [2] be 22 [2] a5 24 [2] b9 23 [2] a5 0c }

  condition:
    any of them
}