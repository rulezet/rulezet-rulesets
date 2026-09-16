rule TTP_XOR_QUAD_CurrentVersionRun_7b14 {
  strings:
    $key_7b14 = { 28 7b [2] 0c 75 [2] 27 59 [2] 09 7b [2] 1d 60 [2] 12 7a [2] 0c 67 [2] 0e 66 [2] 15 60 [2] 09 67 [2] 15 48 }

  condition:
    any of them
}