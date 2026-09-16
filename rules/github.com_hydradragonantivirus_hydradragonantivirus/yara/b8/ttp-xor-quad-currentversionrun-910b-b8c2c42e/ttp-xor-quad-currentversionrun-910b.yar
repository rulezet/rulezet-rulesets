rule TTP_XOR_QUAD_CurrentVersionRun_910b {
  strings:
    $key_910b = { c2 64 [2] e6 6a [2] cd 46 [2] e3 64 [2] f7 7f [2] f8 65 [2] e6 78 [2] e4 79 [2] ff 7f [2] e3 78 [2] ff 57 }

  condition:
    any of them
}