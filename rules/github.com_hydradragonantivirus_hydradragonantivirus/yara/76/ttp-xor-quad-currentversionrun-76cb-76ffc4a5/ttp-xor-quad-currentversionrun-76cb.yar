rule TTP_XOR_QUAD_CurrentVersionRun_76cb {
  strings:
    $key_76cb = { 25 a4 [2] 01 aa [2] 2a 86 [2] 04 a4 [2] 10 bf [2] 1f a5 [2] 01 b8 [2] 03 b9 [2] 18 bf [2] 04 b8 [2] 18 97 }

  condition:
    any of them
}