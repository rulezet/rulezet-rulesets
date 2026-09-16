rule TTP_XOR_QUAD_CurrentVersionRun_2b24 {
  strings:
    $key_2b24 = { 78 4b [2] 5c 45 [2] 77 69 [2] 59 4b [2] 4d 50 [2] 42 4a [2] 5c 57 [2] 5e 56 [2] 45 50 [2] 59 57 [2] 45 78 }

  condition:
    any of them
}