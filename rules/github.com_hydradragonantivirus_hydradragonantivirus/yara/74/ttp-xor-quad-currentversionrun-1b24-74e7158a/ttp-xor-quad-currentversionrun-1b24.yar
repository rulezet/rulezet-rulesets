rule TTP_XOR_QUAD_CurrentVersionRun_1b24 {
  strings:
    $key_1b24 = { 48 4b [2] 6c 45 [2] 47 69 [2] 69 4b [2] 7d 50 [2] 72 4a [2] 6c 57 [2] 6e 56 [2] 75 50 [2] 69 57 [2] 75 78 }

  condition:
    any of them
}