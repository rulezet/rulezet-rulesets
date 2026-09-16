rule TTP_XOR_QUAD_CurrentVersionRun_71cb {
  strings:
    $key_71cb = { 22 a4 [2] 06 aa [2] 2d 86 [2] 03 a4 [2] 17 bf [2] 18 a5 [2] 06 b8 [2] 04 b9 [2] 1f bf [2] 03 b8 [2] 1f 97 }

  condition:
    any of them
}