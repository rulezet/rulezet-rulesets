rule TTP_XOR_QUAD_CurrentVersionRun_2b14 {
  strings:
    $key_2b14 = { 78 7b [2] 5c 75 [2] 77 59 [2] 59 7b [2] 4d 60 [2] 42 7a [2] 5c 67 [2] 5e 66 [2] 45 60 [2] 59 67 [2] 45 48 }

  condition:
    any of them
}