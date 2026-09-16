rule TTP_XOR_QUAD_CurrentVersionRun_f0cb {
  strings:
    $key_f0cb = { a3 a4 [2] 87 aa [2] ac 86 [2] 82 a4 [2] 96 bf [2] 99 a5 [2] 87 b8 [2] 85 b9 [2] 9e bf [2] 82 b8 [2] 9e 97 }

  condition:
    any of them
}