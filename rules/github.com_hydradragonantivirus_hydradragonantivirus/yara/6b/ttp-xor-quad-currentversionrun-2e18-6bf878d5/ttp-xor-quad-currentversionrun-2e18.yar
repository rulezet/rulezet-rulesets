rule TTP_XOR_QUAD_CurrentVersionRun_2e18 {
  strings:
    $key_2e18 = { 7d 77 [2] 59 79 [2] 72 55 [2] 5c 77 [2] 48 6c [2] 47 76 [2] 59 6b [2] 5b 6a [2] 40 6c [2] 5c 6b [2] 40 44 }

  condition:
    any of them
}