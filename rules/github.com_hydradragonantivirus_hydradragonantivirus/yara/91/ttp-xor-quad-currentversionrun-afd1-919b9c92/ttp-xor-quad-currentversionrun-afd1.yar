rule TTP_XOR_QUAD_CurrentVersionRun_afd1 {
  strings:
    $key_afd1 = { fc be [2] d8 b0 [2] f3 9c [2] dd be [2] c9 a5 [2] c6 bf [2] d8 a2 [2] da a3 [2] c1 a5 [2] dd a2 [2] c1 8d }

  condition:
    any of them
}