rule TTP_XOR_QUAD_CurrentVersionRun_2434 {
  strings:
    $key_2434 = { 77 5b [2] 53 55 [2] 78 79 [2] 56 5b [2] 42 40 [2] 4d 5a [2] 53 47 [2] 51 46 [2] 4a 40 [2] 56 47 [2] 4a 68 }

  condition:
    any of them
}