rule TTP_XOR_QUAD_CurrentVersionRun_3df9 {
  strings:
    $key_3df9 = { 6e 96 [2] 4a 98 [2] 61 b4 [2] 4f 96 [2] 5b 8d [2] 54 97 [2] 4a 8a [2] 48 8b [2] 53 8d [2] 4f 8a [2] 53 a5 }

  condition:
    any of them
}