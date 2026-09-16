rule TTP_XOR_QUAD_CurrentVersionRun_5014 {
  strings:
    $key_5014 = { 03 7b [2] 27 75 [2] 0c 59 [2] 22 7b [2] 36 60 [2] 39 7a [2] 27 67 [2] 25 66 [2] 3e 60 [2] 22 67 [2] 3e 48 }

  condition:
    any of them
}