rule TTP_XOR_QUAD_CurrentVersionRun_1fcb {
  strings:
    $key_1fcb = { 4c a4 [2] 68 aa [2] 43 86 [2] 6d a4 [2] 79 bf [2] 76 a5 [2] 68 b8 [2] 6a b9 [2] 71 bf [2] 6d b8 [2] 71 97 }

  condition:
    any of them
}