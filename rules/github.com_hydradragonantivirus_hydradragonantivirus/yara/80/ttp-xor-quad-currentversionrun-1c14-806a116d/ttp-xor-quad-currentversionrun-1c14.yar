rule TTP_XOR_QUAD_CurrentVersionRun_1c14 {
  strings:
    $key_1c14 = { 4f 7b [2] 6b 75 [2] 40 59 [2] 6e 7b [2] 7a 60 [2] 75 7a [2] 6b 67 [2] 69 66 [2] 72 60 [2] 6e 67 [2] 72 48 }

  condition:
    any of them
}