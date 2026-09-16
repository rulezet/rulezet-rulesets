rule TTP_XOR_QUAD_CurrentVersionRun_3714 {
  strings:
    $key_3714 = { 64 7b [2] 40 75 [2] 6b 59 [2] 45 7b [2] 51 60 [2] 5e 7a [2] 40 67 [2] 42 66 [2] 59 60 [2] 45 67 [2] 59 48 }

  condition:
    any of them
}