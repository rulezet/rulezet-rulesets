rule TTP_XOR_QUAD_CurrentVersionRun_67cb {
  strings:
    $key_67cb = { 34 a4 [2] 10 aa [2] 3b 86 [2] 15 a4 [2] 01 bf [2] 0e a5 [2] 10 b8 [2] 12 b9 [2] 09 bf [2] 15 b8 [2] 09 97 }

  condition:
    any of them
}