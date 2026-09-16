rule TTP_XOR_QUAD_CurrentVersionRun_3314 {
  strings:
    $key_3314 = { 60 7b [2] 44 75 [2] 6f 59 [2] 41 7b [2] 55 60 [2] 5a 7a [2] 44 67 [2] 46 66 [2] 5d 60 [2] 41 67 [2] 5d 48 }

  condition:
    any of them
}