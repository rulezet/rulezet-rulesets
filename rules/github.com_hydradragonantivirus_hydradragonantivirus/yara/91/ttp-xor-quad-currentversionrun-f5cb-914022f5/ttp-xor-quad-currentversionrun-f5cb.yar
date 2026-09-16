rule TTP_XOR_QUAD_CurrentVersionRun_f5cb {
  strings:
    $key_f5cb = { a6 a4 [2] 82 aa [2] a9 86 [2] 87 a4 [2] 93 bf [2] 9c a5 [2] 82 b8 [2] 80 b9 [2] 9b bf [2] 87 b8 [2] 9b 97 }

  condition:
    any of them
}