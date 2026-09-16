rule TTP_XOR_QUAD_CurrentVersionRun_7028 {
  strings:
    $key_7028 = { 23 47 [2] 07 49 [2] 2c 65 [2] 02 47 [2] 16 5c [2] 19 46 [2] 07 5b [2] 05 5a [2] 1e 5c [2] 02 5b [2] 1e 74 }

  condition:
    any of them
}