rule TTP_XOR_QUAD_CurrentVersionRun_e0cb {
  strings:
    $key_e0cb = { b3 a4 [2] 97 aa [2] bc 86 [2] 92 a4 [2] 86 bf [2] 89 a5 [2] 97 b8 [2] 95 b9 [2] 8e bf [2] 92 b8 [2] 8e 97 }

  condition:
    any of them
}