rule TTP_XOR_QUAD_CurrentVersionRun_5714 {
  strings:
    $key_5714 = { 04 7b [2] 20 75 [2] 0b 59 [2] 25 7b [2] 31 60 [2] 3e 7a [2] 20 67 [2] 22 66 [2] 39 60 [2] 25 67 [2] 39 48 }

  condition:
    any of them
}