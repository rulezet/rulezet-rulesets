rule TTP_XOR_QUAD_CurrentVersionRun_4b14 {
  strings:
    $key_4b14 = { 18 7b [2] 3c 75 [2] 17 59 [2] 39 7b [2] 2d 60 [2] 22 7a [2] 3c 67 [2] 3e 66 [2] 25 60 [2] 39 67 [2] 25 48 }

  condition:
    any of them
}