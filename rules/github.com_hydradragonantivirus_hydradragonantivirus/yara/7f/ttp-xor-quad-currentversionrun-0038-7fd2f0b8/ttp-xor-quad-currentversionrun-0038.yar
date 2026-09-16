rule TTP_XOR_QUAD_CurrentVersionRun_0038 {
  strings:
    $key_0038 = { 53 57 [2] 77 59 [2] 5c 75 [2] 72 57 [2] 66 4c [2] 69 56 [2] 77 4b [2] 75 4a [2] 6e 4c [2] 72 4b [2] 6e 64 }

  condition:
    any of them
}