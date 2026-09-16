rule TTP_XOR_QUAD_CurrentVersionRun_5f29 {
  strings:
    $key_5f29 = { 0c 46 [2] 28 48 [2] 03 64 [2] 2d 46 [2] 39 5d [2] 36 47 [2] 28 5a [2] 2a 5b [2] 31 5d [2] 2d 5a [2] 31 75 }

  condition:
    any of them
}