rule TTP_XOR_QUAD_CurrentVersionRun_3dcb {
  strings:
    $key_3dcb = { 6e a4 [2] 4a aa [2] 61 86 [2] 4f a4 [2] 5b bf [2] 54 a5 [2] 4a b8 [2] 48 b9 [2] 53 bf [2] 4f b8 [2] 53 97 }

  condition:
    any of them
}