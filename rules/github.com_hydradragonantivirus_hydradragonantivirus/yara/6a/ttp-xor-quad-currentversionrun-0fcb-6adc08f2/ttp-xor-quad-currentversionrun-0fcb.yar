rule TTP_XOR_QUAD_CurrentVersionRun_0fcb {
  strings:
    $key_0fcb = { 5c a4 [2] 78 aa [2] 53 86 [2] 7d a4 [2] 69 bf [2] 66 a5 [2] 78 b8 [2] 7a b9 [2] 61 bf [2] 7d b8 [2] 61 97 }

  condition:
    any of them
}