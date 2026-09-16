rule TTP_XOR_QUAD_CurrentVersionRun_afcb {
  strings:
    $key_afcb = { fc a4 [2] d8 aa [2] f3 86 [2] dd a4 [2] c9 bf [2] c6 a5 [2] d8 b8 [2] da b9 [2] c1 bf [2] dd b8 [2] c1 97 }

  condition:
    any of them
}