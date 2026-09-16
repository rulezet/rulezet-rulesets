rule TTP_XOR_QUAD_CurrentVersionRun_cb1e {
  strings:
    $key_cb1e = { 98 71 [2] bc 7f [2] 97 53 [2] b9 71 [2] ad 6a [2] a2 70 [2] bc 6d [2] be 6c [2] a5 6a [2] b9 6d [2] a5 42 }

  condition:
    any of them
}