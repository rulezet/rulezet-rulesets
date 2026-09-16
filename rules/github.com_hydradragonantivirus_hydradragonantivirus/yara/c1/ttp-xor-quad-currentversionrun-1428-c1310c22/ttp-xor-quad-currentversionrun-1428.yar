rule TTP_XOR_QUAD_CurrentVersionRun_1428 {
  strings:
    $key_1428 = { 47 47 [2] 63 49 [2] 48 65 [2] 66 47 [2] 72 5c [2] 7d 46 [2] 63 5b [2] 61 5a [2] 7a 5c [2] 66 5b [2] 7a 74 }

  condition:
    any of them
}