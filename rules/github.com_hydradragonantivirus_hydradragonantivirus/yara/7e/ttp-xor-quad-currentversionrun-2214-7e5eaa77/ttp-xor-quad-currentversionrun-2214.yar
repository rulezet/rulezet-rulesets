rule TTP_XOR_QUAD_CurrentVersionRun_2214 {
  strings:
    $key_2214 = { 71 7b [2] 55 75 [2] 7e 59 [2] 50 7b [2] 44 60 [2] 4b 7a [2] 55 67 [2] 57 66 [2] 4c 60 [2] 50 67 [2] 4c 48 }

  condition:
    any of them
}