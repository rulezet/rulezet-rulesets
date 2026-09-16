rule TTP_XOR_QUAD_CurrentVersionRun_cb24 {
  strings:
    $key_cb24 = { 98 4b [2] bc 45 [2] 97 69 [2] b9 4b [2] ad 50 [2] a2 4a [2] bc 57 [2] be 56 [2] a5 50 [2] b9 57 [2] a5 78 }

  condition:
    any of them
}