rule TTP_XOR_QUAD_CurrentVersionRun_5ecb {
  strings:
    $key_5ecb = { 0d a4 [2] 29 aa [2] 02 86 [2] 2c a4 [2] 38 bf [2] 37 a5 [2] 29 b8 [2] 2b b9 [2] 30 bf [2] 2c b8 [2] 30 97 }

  condition:
    any of them
}