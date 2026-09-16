rule TTP_XOR_QUAD_CurrentVersionRun_1b28 {
  strings:
    $key_1b28 = { 48 47 [2] 6c 49 [2] 47 65 [2] 69 47 [2] 7d 5c [2] 72 46 [2] 6c 5b [2] 6e 5a [2] 75 5c [2] 69 5b [2] 75 74 }

  condition:
    any of them
}