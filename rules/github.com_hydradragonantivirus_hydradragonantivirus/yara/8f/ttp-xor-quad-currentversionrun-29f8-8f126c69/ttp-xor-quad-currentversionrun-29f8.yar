rule TTP_XOR_QUAD_CurrentVersionRun_29f8 {
  strings:
    $key_29f8 = { 7a 97 [2] 5e 99 [2] 75 b5 [2] 5b 97 [2] 4f 8c [2] 40 96 [2] 5e 8b [2] 5c 8a [2] 47 8c [2] 5b 8b [2] 47 a4 }

  condition:
    any of them
}