rule TTP_XOR_QUAD_CurrentVersionRun_35f8 {
  strings:
    $key_35f8 = { 66 97 [2] 42 99 [2] 69 b5 [2] 47 97 [2] 53 8c [2] 5c 96 [2] 42 8b [2] 40 8a [2] 5b 8c [2] 47 8b [2] 5b a4 }

  condition:
    any of them
}