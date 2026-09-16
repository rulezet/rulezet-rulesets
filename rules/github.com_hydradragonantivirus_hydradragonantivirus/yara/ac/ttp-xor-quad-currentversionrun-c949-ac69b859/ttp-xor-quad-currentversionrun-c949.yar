rule TTP_XOR_QUAD_CurrentVersionRun_c949 {
  strings:
    $key_c949 = { 9a 26 [2] be 28 [2] 95 04 [2] bb 26 [2] af 3d [2] a0 27 [2] be 3a [2] bc 3b [2] a7 3d [2] bb 3a [2] a7 15 }

  condition:
    any of them
}