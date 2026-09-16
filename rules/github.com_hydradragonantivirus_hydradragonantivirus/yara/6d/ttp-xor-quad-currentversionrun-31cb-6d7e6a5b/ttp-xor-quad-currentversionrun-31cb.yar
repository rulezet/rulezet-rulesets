rule TTP_XOR_QUAD_CurrentVersionRun_31cb {
  strings:
    $key_31cb = { 62 a4 [2] 46 aa [2] 6d 86 [2] 43 a4 [2] 57 bf [2] 58 a5 [2] 46 b8 [2] 44 b9 [2] 5f bf [2] 43 b8 [2] 5f 97 }

  condition:
    any of them
}