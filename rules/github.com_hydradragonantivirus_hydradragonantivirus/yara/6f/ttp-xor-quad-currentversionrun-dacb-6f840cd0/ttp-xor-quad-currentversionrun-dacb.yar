rule TTP_XOR_QUAD_CurrentVersionRun_dacb {
  strings:
    $key_dacb = { 89 a4 [2] ad aa [2] 86 86 [2] a8 a4 [2] bc bf [2] b3 a5 [2] ad b8 [2] af b9 [2] b4 bf [2] a8 b8 [2] b4 97 }

  condition:
    any of them
}