rule TTP_XOR_QUAD_CurrentVersionRun_0e14 {
  strings:
    $key_0e14 = { 5d 7b [2] 79 75 [2] 52 59 [2] 7c 7b [2] 68 60 [2] 67 7a [2] 79 67 [2] 7b 66 [2] 60 60 [2] 7c 67 [2] 60 48 }

  condition:
    any of them
}