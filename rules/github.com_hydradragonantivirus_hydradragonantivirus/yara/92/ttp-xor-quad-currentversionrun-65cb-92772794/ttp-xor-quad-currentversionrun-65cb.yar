rule TTP_XOR_QUAD_CurrentVersionRun_65cb {
  strings:
    $key_65cb = { 36 a4 [2] 12 aa [2] 39 86 [2] 17 a4 [2] 03 bf [2] 0c a5 [2] 12 b8 [2] 10 b9 [2] 0b bf [2] 17 b8 [2] 0b 97 }

  condition:
    any of them
}