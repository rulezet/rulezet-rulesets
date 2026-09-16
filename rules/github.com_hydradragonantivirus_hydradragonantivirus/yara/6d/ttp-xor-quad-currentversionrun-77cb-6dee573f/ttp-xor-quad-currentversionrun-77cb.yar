rule TTP_XOR_QUAD_CurrentVersionRun_77cb {
  strings:
    $key_77cb = { 24 a4 [2] 00 aa [2] 2b 86 [2] 05 a4 [2] 11 bf [2] 1e a5 [2] 00 b8 [2] 02 b9 [2] 19 bf [2] 05 b8 [2] 19 97 }

  condition:
    any of them
}