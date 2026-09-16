rule TTP_XOR_QUAD_CurrentVersionRun_a7cb {
  strings:
    $key_a7cb = { f4 a4 [2] d0 aa [2] fb 86 [2] d5 a4 [2] c1 bf [2] ce a5 [2] d0 b8 [2] d2 b9 [2] c9 bf [2] d5 b8 [2] c9 97 }

  condition:
    any of them
}