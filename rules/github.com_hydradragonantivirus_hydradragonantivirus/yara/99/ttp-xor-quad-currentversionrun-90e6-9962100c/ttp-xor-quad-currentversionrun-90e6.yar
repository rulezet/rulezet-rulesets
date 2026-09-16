rule TTP_XOR_QUAD_CurrentVersionRun_90e6 {
  strings:
    $key_90e6 = { c3 89 [2] e7 87 [2] cc ab [2] e2 89 [2] f6 92 [2] f9 88 [2] e7 95 [2] e5 94 [2] fe 92 [2] e2 95 [2] fe ba }

  condition:
    any of them
}