rule TTP_XOR_QUAD_CurrentVersionRun_e314 {
  strings:
    $key_e314 = { b0 7b [2] 94 75 [2] bf 59 [2] 91 7b [2] 85 60 [2] 8a 7a [2] 94 67 [2] 96 66 [2] 8d 60 [2] 91 67 [2] 8d 48 }

  condition:
    any of them
}