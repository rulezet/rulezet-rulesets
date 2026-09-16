rule TTP_XOR_QUAD_CurrentVersionRun_91c5 {
  strings:
    $key_91c5 = { c2 aa [2] e6 a4 [2] cd 88 [2] e3 aa [2] f7 b1 [2] f8 ab [2] e6 b6 [2] e4 b7 [2] ff b1 [2] e3 b6 [2] ff 99 }

  condition:
    any of them
}