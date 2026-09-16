rule TTP_XOR_QUAD_CurrentVersionRun_36cb {
  strings:
    $key_36cb = { 65 a4 [2] 41 aa [2] 6a 86 [2] 44 a4 [2] 50 bf [2] 5f a5 [2] 41 b8 [2] 43 b9 [2] 58 bf [2] 44 b8 [2] 58 97 }

  condition:
    any of them
}