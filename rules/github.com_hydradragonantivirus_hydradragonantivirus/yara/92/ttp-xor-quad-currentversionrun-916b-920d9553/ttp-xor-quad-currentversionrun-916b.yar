rule TTP_XOR_QUAD_CurrentVersionRun_916b {
  strings:
    $key_916b = { c2 04 [2] e6 0a [2] cd 26 [2] e3 04 [2] f7 1f [2] f8 05 [2] e6 18 [2] e4 19 [2] ff 1f [2] e3 18 [2] ff 37 }

  condition:
    any of them
}