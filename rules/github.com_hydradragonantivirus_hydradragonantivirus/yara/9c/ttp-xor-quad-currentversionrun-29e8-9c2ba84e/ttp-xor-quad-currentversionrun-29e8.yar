rule TTP_XOR_QUAD_CurrentVersionRun_29e8 {
  strings:
    $key_29e8 = { 7a 87 [2] 5e 89 [2] 75 a5 [2] 5b 87 [2] 4f 9c [2] 40 86 [2] 5e 9b [2] 5c 9a [2] 47 9c [2] 5b 9b [2] 47 b4 }

  condition:
    any of them
}