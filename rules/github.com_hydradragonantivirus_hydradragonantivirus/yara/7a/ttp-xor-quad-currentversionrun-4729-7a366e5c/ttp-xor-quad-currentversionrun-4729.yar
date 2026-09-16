rule TTP_XOR_QUAD_CurrentVersionRun_4729 {
  strings:
    $key_4729 = { 14 46 [2] 30 48 [2] 1b 64 [2] 35 46 [2] 21 5d [2] 2e 47 [2] 30 5a [2] 32 5b [2] 29 5d [2] 35 5a [2] 29 75 }

  condition:
    any of them
}