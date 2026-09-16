rule TTP_XOR_QUAD_CurrentVersionRun_3de4 {
  strings:
    $key_3de4 = { 6e 8b [2] 4a 85 [2] 61 a9 [2] 4f 8b [2] 5b 90 [2] 54 8a [2] 4a 97 [2] 48 96 [2] 53 90 [2] 4f 97 [2] 53 b8 }

  condition:
    any of them
}