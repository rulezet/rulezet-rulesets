rule TTP_XOR_QUAD_CurrentVersionRun_2429 {
  strings:
    $key_2429 = { 77 46 [2] 53 48 [2] 78 64 [2] 56 46 [2] 42 5d [2] 4d 47 [2] 53 5a [2] 51 5b [2] 4a 5d [2] 56 5a [2] 4a 75 }

  condition:
    any of them
}