rule TTP_XOR_QUAD_CurrentVersionRun_cbc4 {
  strings:
    $key_cbc4 = { 98 ab [2] bc a5 [2] 97 89 [2] b9 ab [2] ad b0 [2] a2 aa [2] bc b7 [2] be b6 [2] a5 b0 [2] b9 b7 [2] a5 98 }

  condition:
    any of them
}