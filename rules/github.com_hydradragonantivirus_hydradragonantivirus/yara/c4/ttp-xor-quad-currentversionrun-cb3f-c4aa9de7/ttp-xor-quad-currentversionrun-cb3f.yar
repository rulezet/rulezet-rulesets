rule TTP_XOR_QUAD_CurrentVersionRun_cb3f {
  strings:
    $key_cb3f = { 98 50 [2] bc 5e [2] 97 72 [2] b9 50 [2] ad 4b [2] a2 51 [2] bc 4c [2] be 4d [2] a5 4b [2] b9 4c [2] a5 63 }

  condition:
    any of them
}