rule TTP_XOR_QUAD_CurrentVersionRun_cbcd {
  strings:
    $key_cbcd = { 98 a2 [2] bc ac [2] 97 80 [2] b9 a2 [2] ad b9 [2] a2 a3 [2] bc be [2] be bf [2] a5 b9 [2] b9 be [2] a5 91 }

  condition:
    any of them
}