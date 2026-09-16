rule TTP_XOR_QUAD_CurrentVersionRun_4b29 {
  strings:
    $key_4b29 = { 18 46 [2] 3c 48 [2] 17 64 [2] 39 46 [2] 2d 5d [2] 22 47 [2] 3c 5a [2] 3e 5b [2] 25 5d [2] 39 5a [2] 25 75 }

  condition:
    any of them
}