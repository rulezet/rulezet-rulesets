rule TTP_XOR_QUAD_CurrentVersionRun_4ccb {
  strings:
    $key_4ccb = { 1f a4 [2] 3b aa [2] 10 86 [2] 3e a4 [2] 2a bf [2] 25 a5 [2] 3b b8 [2] 39 b9 [2] 22 bf [2] 3e b8 [2] 22 97 }

  condition:
    any of them
}