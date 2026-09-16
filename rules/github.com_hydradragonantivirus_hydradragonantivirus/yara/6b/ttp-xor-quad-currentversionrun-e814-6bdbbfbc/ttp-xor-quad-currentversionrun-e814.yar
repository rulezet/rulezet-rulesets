rule TTP_XOR_QUAD_CurrentVersionRun_e814 {
  strings:
    $key_e814 = { bb 7b [2] 9f 75 [2] b4 59 [2] 9a 7b [2] 8e 60 [2] 81 7a [2] 9f 67 [2] 9d 66 [2] 86 60 [2] 9a 67 [2] 86 48 }

  condition:
    any of them
}