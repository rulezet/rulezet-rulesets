rule TTP_XOR_QUAD_CurrentVersionRun_cb05 {
  strings:
    $key_cb05 = { 98 6a [2] bc 64 [2] 97 48 [2] b9 6a [2] ad 71 [2] a2 6b [2] bc 76 [2] be 77 [2] a5 71 [2] b9 76 [2] a5 59 }

  condition:
    any of them
}