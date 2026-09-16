rule TTP_XOR_QUAD_CurrentVersionRun_cb0e {
  strings:
    $key_cb0e = { 98 61 [2] bc 6f [2] 97 43 [2] b9 61 [2] ad 7a [2] a2 60 [2] bc 7d [2] be 7c [2] a5 7a [2] b9 7d [2] a5 52 }

  condition:
    any of them
}