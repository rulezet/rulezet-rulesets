rule TTP_XOR_QUAD_CurrentVersionRun_ebcb {
  strings:
    $key_ebcb = { b8 a4 [2] 9c aa [2] b7 86 [2] 99 a4 [2] 8d bf [2] 82 a5 [2] 9c b8 [2] 9e b9 [2] 85 bf [2] 99 b8 [2] 85 97 }

  condition:
    any of them
}