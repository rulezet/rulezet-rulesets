rule TTP_XOR_QUAD_CurrentVersionRun_5829 {
  strings:
    $key_5829 = { 0b 46 [2] 2f 48 [2] 04 64 [2] 2a 46 [2] 3e 5d [2] 31 47 [2] 2f 5a [2] 2d 5b [2] 36 5d [2] 2a 5a [2] 36 75 }

  condition:
    any of them
}