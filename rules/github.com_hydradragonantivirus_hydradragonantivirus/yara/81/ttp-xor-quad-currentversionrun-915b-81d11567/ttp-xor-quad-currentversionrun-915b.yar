rule TTP_XOR_QUAD_CurrentVersionRun_915b {
  strings:
    $key_915b = { c2 34 [2] e6 3a [2] cd 16 [2] e3 34 [2] f7 2f [2] f8 35 [2] e6 28 [2] e4 29 [2] ff 2f [2] e3 28 [2] ff 07 }

  condition:
    any of them
}