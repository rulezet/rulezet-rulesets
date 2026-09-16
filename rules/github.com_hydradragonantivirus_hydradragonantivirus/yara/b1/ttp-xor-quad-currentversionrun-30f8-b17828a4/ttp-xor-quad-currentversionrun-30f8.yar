rule TTP_XOR_QUAD_CurrentVersionRun_30f8 {
  strings:
    $key_30f8 = { 63 97 [2] 47 99 [2] 6c b5 [2] 42 97 [2] 56 8c [2] 59 96 [2] 47 8b [2] 45 8a [2] 5e 8c [2] 42 8b [2] 5e a4 }

  condition:
    any of them
}