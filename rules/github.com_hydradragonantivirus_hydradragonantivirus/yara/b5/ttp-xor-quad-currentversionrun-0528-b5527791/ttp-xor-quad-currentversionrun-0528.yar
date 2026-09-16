rule TTP_XOR_QUAD_CurrentVersionRun_0528 {
  strings:
    $key_0528 = { 56 47 [2] 72 49 [2] 59 65 [2] 77 47 [2] 63 5c [2] 6c 46 [2] 72 5b [2] 70 5a [2] 6b 5c [2] 77 5b [2] 6b 74 }

  condition:
    any of them
}