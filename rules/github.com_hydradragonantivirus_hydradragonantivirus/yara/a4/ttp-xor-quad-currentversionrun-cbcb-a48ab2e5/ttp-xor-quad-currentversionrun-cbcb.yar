rule TTP_XOR_QUAD_CurrentVersionRun_cbcb {
  strings:
    $key_cbcb = { 98 a4 [2] bc aa [2] 97 86 [2] b9 a4 [2] ad bf [2] a2 a5 [2] bc b8 [2] be b9 [2] a5 bf [2] b9 b8 [2] a5 97 }

  condition:
    any of them
}