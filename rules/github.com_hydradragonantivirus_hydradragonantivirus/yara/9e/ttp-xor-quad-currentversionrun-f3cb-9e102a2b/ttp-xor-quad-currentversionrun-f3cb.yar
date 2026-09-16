rule TTP_XOR_QUAD_CurrentVersionRun_f3cb {
  strings:
    $key_f3cb = { a0 a4 [2] 84 aa [2] af 86 [2] 81 a4 [2] 95 bf [2] 9a a5 [2] 84 b8 [2] 86 b9 [2] 9d bf [2] 81 b8 [2] 9d 97 }

  condition:
    any of them
}