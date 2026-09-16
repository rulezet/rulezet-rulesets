rule TTP_XOR_QUAD_CurrentVersionRun_52cb {
  strings:
    $key_52cb = { 01 a4 [2] 25 aa [2] 0e 86 [2] 20 a4 [2] 34 bf [2] 3b a5 [2] 25 b8 [2] 27 b9 [2] 3c bf [2] 20 b8 [2] 3c 97 }

  condition:
    any of them
}