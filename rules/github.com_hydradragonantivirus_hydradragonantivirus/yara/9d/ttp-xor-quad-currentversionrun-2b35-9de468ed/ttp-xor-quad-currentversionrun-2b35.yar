rule TTP_XOR_QUAD_CurrentVersionRun_2b35 {
  strings:
    $key_2b35 = { 78 5a [2] 5c 54 [2] 77 78 [2] 59 5a [2] 4d 41 [2] 42 5b [2] 5c 46 [2] 5e 47 [2] 45 41 [2] 59 46 [2] 45 69 }

  condition:
    any of them
}