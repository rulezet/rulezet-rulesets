rule TTP_XOR_QUAD_CurrentVersionRun_c9c5 {
  strings:
    $key_c9c5 = { 9a aa [2] be a4 [2] 95 88 [2] bb aa [2] af b1 [2] a0 ab [2] be b6 [2] bc b7 [2] a7 b1 [2] bb b6 [2] a7 99 }

  condition:
    any of them
}