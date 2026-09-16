rule TTP_XOR_QUAD_CurrentVersionRun_1ccb {
  strings:
    $key_1ccb = { 4f a4 [2] 6b aa [2] 40 86 [2] 6e a4 [2] 7a bf [2] 75 a5 [2] 6b b8 [2] 69 b9 [2] 72 bf [2] 6e b8 [2] 72 97 }

  condition:
    any of them
}