rule TTP_XOR_QUAD_CurrentVersionRun_afe2 {
  strings:
    $key_afe2 = { fc 8d [2] d8 83 [2] f3 af [2] dd 8d [2] c9 96 [2] c6 8c [2] d8 91 [2] da 90 [2] c1 96 [2] dd 91 [2] c1 be }

  condition:
    any of them
}