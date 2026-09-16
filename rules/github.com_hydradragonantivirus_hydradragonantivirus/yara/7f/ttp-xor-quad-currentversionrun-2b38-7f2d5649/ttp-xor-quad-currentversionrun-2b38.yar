rule TTP_XOR_QUAD_CurrentVersionRun_2b38 {
  strings:
    $key_2b38 = { 78 57 [2] 5c 59 [2] 77 75 [2] 59 57 [2] 4d 4c [2] 42 56 [2] 5c 4b [2] 5e 4a [2] 45 4c [2] 59 4b [2] 45 64 }

  condition:
    any of them
}