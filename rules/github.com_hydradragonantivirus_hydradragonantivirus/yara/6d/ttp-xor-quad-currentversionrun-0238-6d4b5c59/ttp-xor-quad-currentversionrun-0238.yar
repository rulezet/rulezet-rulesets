rule TTP_XOR_QUAD_CurrentVersionRun_0238 {
  strings:
    $key_0238 = { 51 57 [2] 75 59 [2] 5e 75 [2] 70 57 [2] 64 4c [2] 6b 56 [2] 75 4b [2] 77 4a [2] 6c 4c [2] 70 4b [2] 6c 64 }

  condition:
    any of them
}