rule TTP_XOR_QUAD_CurrentVersionRun_7ecb {
  strings:
    $key_7ecb = { 2d a4 [2] 09 aa [2] 22 86 [2] 0c a4 [2] 18 bf [2] 17 a5 [2] 09 b8 [2] 0b b9 [2] 10 bf [2] 0c b8 [2] 10 97 }

  condition:
    any of them
}