rule TTP_XOR_QUAD_CurrentVersionRun_3bcb {
  strings:
    $key_3bcb = { 68 a4 [2] 4c aa [2] 67 86 [2] 49 a4 [2] 5d bf [2] 52 a5 [2] 4c b8 [2] 4e b9 [2] 55 bf [2] 49 b8 [2] 55 97 }

  condition:
    any of them
}