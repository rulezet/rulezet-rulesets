rule TTP_XOR_QUAD_CurrentVersionRun_35f9 {
  strings:
    $key_35f9 = { 66 96 [2] 42 98 [2] 69 b4 [2] 47 96 [2] 53 8d [2] 5c 97 [2] 42 8a [2] 40 8b [2] 5b 8d [2] 47 8a [2] 5b a5 }

  condition:
    any of them
}