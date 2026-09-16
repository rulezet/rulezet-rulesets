rule TTP_XOR_QUAD_CurrentVersionRun_2408 {
  strings:
    $key_2408 = { 77 67 [2] 53 69 [2] 78 45 [2] 56 67 [2] 42 7c [2] 4d 66 [2] 53 7b [2] 51 7a [2] 4a 7c [2] 56 7b [2] 4a 54 }

  condition:
    any of them
}