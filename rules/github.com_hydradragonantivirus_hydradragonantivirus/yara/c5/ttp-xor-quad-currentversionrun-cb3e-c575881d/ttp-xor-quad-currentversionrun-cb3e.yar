rule TTP_XOR_QUAD_CurrentVersionRun_cb3e {
  strings:
    $key_cb3e = { 98 51 [2] bc 5f [2] 97 73 [2] b9 51 [2] ad 4a [2] a2 50 [2] bc 4d [2] be 4c [2] a5 4a [2] b9 4d [2] a5 62 }

  condition:
    any of them
}