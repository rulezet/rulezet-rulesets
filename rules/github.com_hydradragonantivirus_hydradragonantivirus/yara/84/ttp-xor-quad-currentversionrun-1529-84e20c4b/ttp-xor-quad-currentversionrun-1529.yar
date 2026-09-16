rule TTP_XOR_QUAD_CurrentVersionRun_1529 {
  strings:
    $key_1529 = { 46 46 [2] 62 48 [2] 49 64 [2] 67 46 [2] 73 5d [2] 7c 47 [2] 62 5a [2] 60 5b [2] 7b 5d [2] 67 5a [2] 7b 75 }

  condition:
    any of them
}