rule TTP_XOR_QUAD_CurrentVersionRun_0e29 {
  strings:
    $key_0e29 = { 5d 46 [2] 79 48 [2] 52 64 [2] 7c 46 [2] 68 5d [2] 67 47 [2] 79 5a [2] 7b 5b [2] 60 5d [2] 7c 5a [2] 60 75 }

  condition:
    any of them
}