rule TTP_XOR_QUAD_CurrentVersionRun_6a28 {
  strings:
    $key_6a28 = { 39 47 [2] 1d 49 [2] 36 65 [2] 18 47 [2] 0c 5c [2] 03 46 [2] 1d 5b [2] 1f 5a [2] 04 5c [2] 18 5b [2] 04 74 }

  condition:
    any of them
}