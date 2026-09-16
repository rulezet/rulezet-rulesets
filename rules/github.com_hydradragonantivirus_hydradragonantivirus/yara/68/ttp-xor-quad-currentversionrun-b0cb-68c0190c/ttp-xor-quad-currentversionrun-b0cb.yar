rule TTP_XOR_QUAD_CurrentVersionRun_b0cb {
  strings:
    $key_b0cb = { e3 a4 [2] c7 aa [2] ec 86 [2] c2 a4 [2] d6 bf [2] d9 a5 [2] c7 b8 [2] c5 b9 [2] de bf [2] c2 b8 [2] de 97 }

  condition:
    any of them
}