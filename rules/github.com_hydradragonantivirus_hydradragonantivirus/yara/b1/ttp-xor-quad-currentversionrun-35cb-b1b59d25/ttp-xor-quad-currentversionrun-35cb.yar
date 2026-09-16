rule TTP_XOR_QUAD_CurrentVersionRun_35cb {
  strings:
    $key_35cb = { 66 a4 [2] 42 aa [2] 69 86 [2] 47 a4 [2] 53 bf [2] 5c a5 [2] 42 b8 [2] 40 b9 [2] 5b bf [2] 47 b8 [2] 5b 97 }

  condition:
    any of them
}