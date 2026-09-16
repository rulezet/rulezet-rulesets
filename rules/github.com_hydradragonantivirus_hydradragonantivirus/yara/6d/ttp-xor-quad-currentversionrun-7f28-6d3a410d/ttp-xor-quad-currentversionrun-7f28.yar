rule TTP_XOR_QUAD_CurrentVersionRun_7f28 {
  strings:
    $key_7f28 = { 2c 47 [2] 08 49 [2] 23 65 [2] 0d 47 [2] 19 5c [2] 16 46 [2] 08 5b [2] 0a 5a [2] 11 5c [2] 0d 5b [2] 11 74 }

  condition:
    any of them
}