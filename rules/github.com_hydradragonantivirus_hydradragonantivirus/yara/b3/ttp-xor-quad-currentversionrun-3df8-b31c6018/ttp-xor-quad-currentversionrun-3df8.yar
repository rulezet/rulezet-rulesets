rule TTP_XOR_QUAD_CurrentVersionRun_3df8 {
  strings:
    $key_3df8 = { 6e 97 [2] 4a 99 [2] 61 b5 [2] 4f 97 [2] 5b 8c [2] 54 96 [2] 4a 8b [2] 48 8a [2] 53 8c [2] 4f 8b [2] 53 a4 }

  condition:
    any of them
}