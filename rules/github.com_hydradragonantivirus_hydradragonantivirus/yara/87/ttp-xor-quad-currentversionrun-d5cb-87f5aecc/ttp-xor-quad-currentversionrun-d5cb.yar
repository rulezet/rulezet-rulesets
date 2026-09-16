rule TTP_XOR_QUAD_CurrentVersionRun_d5cb {
  strings:
    $key_d5cb = { 86 a4 [2] a2 aa [2] 89 86 [2] a7 a4 [2] b3 bf [2] bc a5 [2] a2 b8 [2] a0 b9 [2] bb bf [2] a7 b8 [2] bb 97 }

  condition:
    any of them
}