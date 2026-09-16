rule TTP_XOR_QUAD_CurrentVersionRun_6a35 {
  strings:
    $key_6a35 = { 39 5a [2] 1d 54 [2] 36 78 [2] 18 5a [2] 0c 41 [2] 03 5b [2] 1d 46 [2] 1f 47 [2] 04 41 [2] 18 46 [2] 04 69 }

  condition:
    any of them
}