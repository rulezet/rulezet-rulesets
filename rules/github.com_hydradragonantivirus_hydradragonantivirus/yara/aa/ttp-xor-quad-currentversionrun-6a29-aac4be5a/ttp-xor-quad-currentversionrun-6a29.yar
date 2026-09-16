rule TTP_XOR_QUAD_CurrentVersionRun_6a29 {
  strings:
    $key_6a29 = { 39 46 [2] 1d 48 [2] 36 64 [2] 18 46 [2] 0c 5d [2] 03 47 [2] 1d 5a [2] 1f 5b [2] 04 5d [2] 18 5a [2] 04 75 }

  condition:
    any of them
}