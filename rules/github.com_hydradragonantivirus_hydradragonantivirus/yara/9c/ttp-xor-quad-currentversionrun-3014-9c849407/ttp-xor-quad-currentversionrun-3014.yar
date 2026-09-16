rule TTP_XOR_QUAD_CurrentVersionRun_3014 {
  strings:
    $key_3014 = { 63 7b [2] 47 75 [2] 6c 59 [2] 42 7b [2] 56 60 [2] 59 7a [2] 47 67 [2] 45 66 [2] 5e 60 [2] 42 67 [2] 5e 48 }

  condition:
    any of them
}