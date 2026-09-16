rule TTP_XOR_QUAD_CurrentVersionRun_5acb {
  strings:
    $key_5acb = { 09 a4 [2] 2d aa [2] 06 86 [2] 28 a4 [2] 3c bf [2] 33 a5 [2] 2d b8 [2] 2f b9 [2] 34 bf [2] 28 b8 [2] 34 97 }

  condition:
    any of them
}