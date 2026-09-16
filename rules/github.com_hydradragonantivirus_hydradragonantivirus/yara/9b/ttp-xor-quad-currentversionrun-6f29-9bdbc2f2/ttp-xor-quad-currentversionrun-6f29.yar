rule TTP_XOR_QUAD_CurrentVersionRun_6f29 {
  strings:
    $key_6f29 = { 3c 46 [2] 18 48 [2] 33 64 [2] 1d 46 [2] 09 5d [2] 06 47 [2] 18 5a [2] 1a 5b [2] 01 5d [2] 1d 5a [2] 01 75 }

  condition:
    any of them
}