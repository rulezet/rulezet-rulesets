rule TTP_XOR_QUAD_CurrentVersionRun_aecb {
  strings:
    $key_aecb = { fd a4 [2] d9 aa [2] f2 86 [2] dc a4 [2] c8 bf [2] c7 a5 [2] d9 b8 [2] db b9 [2] c0 bf [2] dc b8 [2] c0 97 }

  condition:
    any of them
}