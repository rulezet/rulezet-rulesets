rule TTP_XOR_QUAD_CurrentVersionRun_1814 {
  strings:
    $key_1814 = { 4b 7b [2] 6f 75 [2] 44 59 [2] 6a 7b [2] 7e 60 [2] 71 7a [2] 6f 67 [2] 6d 66 [2] 76 60 [2] 6a 67 [2] 76 48 }

  condition:
    any of them
}