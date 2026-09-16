rule TTP_XOR_QUAD_CurrentVersionRun_f6cb {
  strings:
    $key_f6cb = { a5 a4 [2] 81 aa [2] aa 86 [2] 84 a4 [2] 90 bf [2] 9f a5 [2] 81 b8 [2] 83 b9 [2] 98 bf [2] 84 b8 [2] 98 97 }

  condition:
    any of them
}