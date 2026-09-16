rule TTP_XOR_QUAD_CurrentVersionRun_cb38 {
  strings:
    $key_cb38 = { 98 57 [2] bc 59 [2] 97 75 [2] b9 57 [2] ad 4c [2] a2 56 [2] bc 4b [2] be 4a [2] a5 4c [2] b9 4b [2] a5 64 }

  condition:
    any of them
}