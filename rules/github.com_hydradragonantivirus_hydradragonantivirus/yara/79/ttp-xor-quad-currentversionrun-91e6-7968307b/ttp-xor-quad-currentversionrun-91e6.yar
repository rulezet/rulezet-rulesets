rule TTP_XOR_QUAD_CurrentVersionRun_91e6 {
  strings:
    $key_91e6 = { c2 89 [2] e6 87 [2] cd ab [2] e3 89 [2] f7 92 [2] f8 88 [2] e6 95 [2] e4 94 [2] ff 92 [2] e3 95 [2] ff ba }

  condition:
    any of them
}