rule TTP_XOR_QUAD_CurrentVersionRun_4bcb {
  strings:
    $key_4bcb = { 18 a4 [2] 3c aa [2] 17 86 [2] 39 a4 [2] 2d bf [2] 22 a5 [2] 3c b8 [2] 3e b9 [2] 25 bf [2] 39 b8 [2] 25 97 }

  condition:
    any of them
}