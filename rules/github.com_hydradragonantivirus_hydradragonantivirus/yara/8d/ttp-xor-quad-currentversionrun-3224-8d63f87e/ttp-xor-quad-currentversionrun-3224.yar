rule TTP_XOR_QUAD_CurrentVersionRun_3224 {
  strings:
    $key_3224 = { 61 4b [2] 45 45 [2] 6e 69 [2] 40 4b [2] 54 50 [2] 5b 4a [2] 45 57 [2] 47 56 [2] 5c 50 [2] 40 57 [2] 5c 78 }

  condition:
    any of them
}