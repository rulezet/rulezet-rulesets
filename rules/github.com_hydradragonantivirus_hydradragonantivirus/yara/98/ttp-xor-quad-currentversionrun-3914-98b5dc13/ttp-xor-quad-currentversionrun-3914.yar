rule TTP_XOR_QUAD_CurrentVersionRun_3914 {
  strings:
    $key_3914 = { 6a 7b [2] 4e 75 [2] 65 59 [2] 4b 7b [2] 5f 60 [2] 50 7a [2] 4e 67 [2] 4c 66 [2] 57 60 [2] 4b 67 [2] 57 48 }

  condition:
    any of them
}