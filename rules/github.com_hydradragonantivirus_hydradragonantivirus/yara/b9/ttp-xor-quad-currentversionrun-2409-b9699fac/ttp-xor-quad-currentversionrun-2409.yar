rule TTP_XOR_QUAD_CurrentVersionRun_2409 {
  strings:
    $key_2409 = { 77 66 [2] 53 68 [2] 78 44 [2] 56 66 [2] 42 7d [2] 4d 67 [2] 53 7a [2] 51 7b [2] 4a 7d [2] 56 7a [2] 4a 55 }

  condition:
    any of them
}