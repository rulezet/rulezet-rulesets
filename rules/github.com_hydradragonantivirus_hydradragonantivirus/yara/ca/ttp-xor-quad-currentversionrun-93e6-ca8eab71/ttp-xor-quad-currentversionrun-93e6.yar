rule TTP_XOR_QUAD_CurrentVersionRun_93e6 {
  strings:
    $key_93e6 = { c0 89 [2] e4 87 [2] cf ab [2] e1 89 [2] f5 92 [2] fa 88 [2] e4 95 [2] e6 94 [2] fd 92 [2] e1 95 [2] fd ba }

  condition:
    any of them
}