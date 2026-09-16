rule TTP_XOR_QUAD_CurrentVersionRun_6a14 {
  strings:
    $key_6a14 = { 39 7b [2] 1d 75 [2] 36 59 [2] 18 7b [2] 0c 60 [2] 03 7a [2] 1d 67 [2] 1f 66 [2] 04 60 [2] 18 67 [2] 04 48 }

  condition:
    any of them
}