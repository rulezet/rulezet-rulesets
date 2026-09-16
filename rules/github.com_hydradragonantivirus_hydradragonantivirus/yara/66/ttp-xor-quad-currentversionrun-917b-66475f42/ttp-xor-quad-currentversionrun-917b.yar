rule TTP_XOR_QUAD_CurrentVersionRun_917b {
  strings:
    $key_917b = { c2 14 [2] e6 1a [2] cd 36 [2] e3 14 [2] f7 0f [2] f8 15 [2] e6 08 [2] e4 09 [2] ff 0f [2] e3 08 [2] ff 27 }

  condition:
    any of them
}