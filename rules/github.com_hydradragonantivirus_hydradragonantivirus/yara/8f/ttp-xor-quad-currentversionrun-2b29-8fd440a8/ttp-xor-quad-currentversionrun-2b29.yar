rule TTP_XOR_QUAD_CurrentVersionRun_2b29 {
  strings:
    $key_2b29 = { 78 46 [2] 5c 48 [2] 77 64 [2] 59 46 [2] 4d 5d [2] 42 47 [2] 5c 5a [2] 5e 5b [2] 45 5d [2] 59 5a [2] 45 75 }

  condition:
    any of them
}