rule TTP_XOR_QUAD_CurrentVersionRun_7e29 {
  strings:
    $key_7e29 = { 2d 46 [2] 09 48 [2] 22 64 [2] 0c 46 [2] 18 5d [2] 17 47 [2] 09 5a [2] 0b 5b [2] 10 5d [2] 0c 5a [2] 10 75 }

  condition:
    any of them
}