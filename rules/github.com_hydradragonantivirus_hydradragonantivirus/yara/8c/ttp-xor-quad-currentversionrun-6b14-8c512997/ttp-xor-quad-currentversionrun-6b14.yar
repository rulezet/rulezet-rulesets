rule TTP_XOR_QUAD_CurrentVersionRun_6b14 {
  strings:
    $key_6b14 = { 38 7b [2] 1c 75 [2] 37 59 [2] 19 7b [2] 0d 60 [2] 02 7a [2] 1c 67 [2] 1e 66 [2] 05 60 [2] 19 67 [2] 05 48 }

  condition:
    any of them
}