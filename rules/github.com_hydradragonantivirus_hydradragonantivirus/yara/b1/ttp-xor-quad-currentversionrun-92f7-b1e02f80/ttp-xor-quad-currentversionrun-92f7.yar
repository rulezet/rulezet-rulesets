rule TTP_XOR_QUAD_CurrentVersionRun_92f7 {
  strings:
    $key_92f7 = { c1 98 [2] e5 96 [2] ce ba [2] e0 98 [2] f4 83 [2] fb 99 [2] e5 84 [2] e7 85 [2] fc 83 [2] e0 84 [2] fc ab }

  condition:
    any of them
}