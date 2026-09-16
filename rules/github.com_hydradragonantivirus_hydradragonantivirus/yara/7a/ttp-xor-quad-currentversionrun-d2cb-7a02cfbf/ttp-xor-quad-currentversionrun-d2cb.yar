rule TTP_XOR_QUAD_CurrentVersionRun_d2cb {
  strings:
    $key_d2cb = { 81 a4 [2] a5 aa [2] 8e 86 [2] a0 a4 [2] b4 bf [2] bb a5 [2] a5 b8 [2] a7 b9 [2] bc bf [2] a0 b8 [2] bc 97 }

  condition:
    any of them
}