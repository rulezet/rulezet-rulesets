rule TTP_XOR_QUAD_CurrentVersionRun_2428 {
  strings:
    $key_2428 = { 77 47 [2] 53 49 [2] 78 65 [2] 56 47 [2] 42 5c [2] 4d 46 [2] 53 5b [2] 51 5a [2] 4a 5c [2] 56 5b [2] 4a 74 }

  condition:
    any of them
}