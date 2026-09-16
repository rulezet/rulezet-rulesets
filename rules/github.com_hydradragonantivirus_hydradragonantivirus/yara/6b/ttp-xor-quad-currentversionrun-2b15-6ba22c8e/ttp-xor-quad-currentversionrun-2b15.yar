rule TTP_XOR_QUAD_CurrentVersionRun_2b15 {
  strings:
    $key_2b15 = { 78 7a [2] 5c 74 [2] 77 58 [2] 59 7a [2] 4d 61 [2] 42 7b [2] 5c 66 [2] 5e 67 [2] 45 61 [2] 59 66 [2] 45 49 }

  condition:
    any of them
}