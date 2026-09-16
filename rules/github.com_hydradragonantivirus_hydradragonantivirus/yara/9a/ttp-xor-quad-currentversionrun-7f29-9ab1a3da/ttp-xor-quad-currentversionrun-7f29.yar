rule TTP_XOR_QUAD_CurrentVersionRun_7f29 {
  strings:
    $key_7f29 = { 2c 46 [2] 08 48 [2] 23 64 [2] 0d 46 [2] 19 5d [2] 16 47 [2] 08 5a [2] 0a 5b [2] 11 5d [2] 0d 5a [2] 11 75 }

  condition:
    any of them
}