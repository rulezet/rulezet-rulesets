rule TTP_XOR_QUAD_CurrentVersionRun_92e6 {
  strings:
    $key_92e6 = { c1 89 [2] e5 87 [2] ce ab [2] e0 89 [2] f4 92 [2] fb 88 [2] e5 95 [2] e7 94 [2] fc 92 [2] e0 95 [2] fc ba }

  condition:
    any of them
}