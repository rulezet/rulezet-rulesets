rule TTP_XOR_QUAD_CurrentVersionRun_afe3 {
  strings:
    $key_afe3 = { fc 8c [2] d8 82 [2] f3 ae [2] dd 8c [2] c9 97 [2] c6 8d [2] d8 90 [2] da 91 [2] c1 97 [2] dd 90 [2] c1 bf }

  condition:
    any of them
}