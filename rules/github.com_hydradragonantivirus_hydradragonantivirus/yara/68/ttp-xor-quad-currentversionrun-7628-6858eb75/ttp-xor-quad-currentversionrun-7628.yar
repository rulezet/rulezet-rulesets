rule TTP_XOR_QUAD_CurrentVersionRun_7628 {
  strings:
    $key_7628 = { 25 47 [2] 01 49 [2] 2a 65 [2] 04 47 [2] 10 5c [2] 1f 46 [2] 01 5b [2] 03 5a [2] 18 5c [2] 04 5b [2] 18 74 }

  condition:
    any of them
}