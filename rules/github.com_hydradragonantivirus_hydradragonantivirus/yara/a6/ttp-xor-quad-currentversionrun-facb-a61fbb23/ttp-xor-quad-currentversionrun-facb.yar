rule TTP_XOR_QUAD_CurrentVersionRun_facb {
  strings:
    $key_facb = { a9 a4 [2] 8d aa [2] a6 86 [2] 88 a4 [2] 9c bf [2] 93 a5 [2] 8d b8 [2] 8f b9 [2] 94 bf [2] 88 b8 [2] 94 97 }

  condition:
    any of them
}