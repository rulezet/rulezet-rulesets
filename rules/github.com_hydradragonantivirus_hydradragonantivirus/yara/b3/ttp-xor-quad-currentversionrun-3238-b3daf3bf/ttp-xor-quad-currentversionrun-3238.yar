rule TTP_XOR_QUAD_CurrentVersionRun_3238 {
  strings:
    $key_3238 = { 61 57 [2] 45 59 [2] 6e 75 [2] 40 57 [2] 54 4c [2] 5b 56 [2] 45 4b [2] 47 4a [2] 5c 4c [2] 40 4b [2] 5c 64 }

  condition:
    any of them
}