rule TTP_XOR_QUAD_CurrentVersionRun_2bcb {
  strings:
    $key_2bcb = { 78 a4 [2] 5c aa [2] 77 86 [2] 59 a4 [2] 4d bf [2] 42 a5 [2] 5c b8 [2] 5e b9 [2] 45 bf [2] 59 b8 [2] 45 97 }

  condition:
    any of them
}