rule TTP_XOR_QUAD_CurrentVersionRun_2614 {
  strings:
    $key_2614 = { 75 7b [2] 51 75 [2] 7a 59 [2] 54 7b [2] 40 60 [2] 4f 7a [2] 51 67 [2] 53 66 [2] 48 60 [2] 54 67 [2] 48 48 }

  condition:
    any of them
}