rule TTP_XOR_QUAD_CurrentVersionRun_2814 {
  strings:
    $key_2814 = { 7b 7b [2] 5f 75 [2] 74 59 [2] 5a 7b [2] 4e 60 [2] 41 7a [2] 5f 67 [2] 5d 66 [2] 46 60 [2] 5a 67 [2] 46 48 }

  condition:
    any of them
}