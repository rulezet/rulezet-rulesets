rule TTP_XOR_QUAD_CurrentVersionRun_1628 {
  strings:
    $key_1628 = { 45 47 [2] 61 49 [2] 4a 65 [2] 64 47 [2] 70 5c [2] 7f 46 [2] 61 5b [2] 63 5a [2] 78 5c [2] 64 5b [2] 78 74 }

  condition:
    any of them
}