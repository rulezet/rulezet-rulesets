rule TTP_XOR_QUAD_CurrentVersionRun_cb29 {
  strings:
    $key_cb29 = { 98 46 [2] bc 48 [2] 97 64 [2] b9 46 [2] ad 5d [2] a2 47 [2] bc 5a [2] be 5b [2] a5 5d [2] b9 5a [2] a5 75 }

  condition:
    any of them
}