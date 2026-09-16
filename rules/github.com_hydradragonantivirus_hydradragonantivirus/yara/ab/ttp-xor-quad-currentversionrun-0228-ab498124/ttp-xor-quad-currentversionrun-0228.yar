rule TTP_XOR_QUAD_CurrentVersionRun_0228 {
  strings:
    $key_0228 = { 51 47 [2] 75 49 [2] 5e 65 [2] 70 47 [2] 64 5c [2] 6b 46 [2] 75 5b [2] 77 5a [2] 6c 5c [2] 70 5b [2] 6c 74 }

  condition:
    any of them
}