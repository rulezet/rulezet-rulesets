rule TTP_XOR_QUAD_CurrentVersionRun_becb {
  strings:
    $key_becb = { ed a4 [2] c9 aa [2] e2 86 [2] cc a4 [2] d8 bf [2] d7 a5 [2] c9 b8 [2] cb b9 [2] d0 bf [2] cc b8 [2] d0 97 }

  condition:
    any of them
}