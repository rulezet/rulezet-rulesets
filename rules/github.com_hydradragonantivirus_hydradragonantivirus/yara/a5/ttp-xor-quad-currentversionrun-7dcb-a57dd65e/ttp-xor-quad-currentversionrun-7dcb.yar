rule TTP_XOR_QUAD_CurrentVersionRun_7dcb {
  strings:
    $key_7dcb = { 2e a4 [2] 0a aa [2] 21 86 [2] 0f a4 [2] 1b bf [2] 14 a5 [2] 0a b8 [2] 08 b9 [2] 13 bf [2] 0f b8 [2] 13 97 }

  condition:
    any of them
}