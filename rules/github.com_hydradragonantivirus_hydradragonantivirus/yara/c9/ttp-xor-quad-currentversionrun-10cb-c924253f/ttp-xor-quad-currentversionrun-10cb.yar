rule TTP_XOR_QUAD_CurrentVersionRun_10cb {
  strings:
    $key_10cb = { 43 a4 [2] 67 aa [2] 4c 86 [2] 62 a4 [2] 76 bf [2] 79 a5 [2] 67 b8 [2] 65 b9 [2] 7e bf [2] 62 b8 [2] 7e 97 }

  condition:
    any of them
}