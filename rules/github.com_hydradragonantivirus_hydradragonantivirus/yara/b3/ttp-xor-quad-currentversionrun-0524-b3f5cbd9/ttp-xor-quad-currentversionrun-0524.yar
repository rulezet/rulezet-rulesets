rule TTP_XOR_QUAD_CurrentVersionRun_0524 {
  strings:
    $key_0524 = { 56 4b [2] 72 45 [2] 59 69 [2] 77 4b [2] 63 50 [2] 6c 4a [2] 72 57 [2] 70 56 [2] 6b 50 [2] 77 57 [2] 6b 78 }

  condition:
    any of them
}