rule TTP_XOR_QUAD_CurrentVersionRun_2414 {
  strings:
    $key_2414 = { 77 7b [2] 53 75 [2] 78 59 [2] 56 7b [2] 42 60 [2] 4d 7a [2] 53 67 [2] 51 66 [2] 4a 60 [2] 56 67 [2] 4a 48 }

  condition:
    any of them
}