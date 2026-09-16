rule TTP_XOR_QUAD_CurrentVersionRun_15f9 {
  strings:
    $key_15f9 = { 46 96 [2] 62 98 [2] 49 b4 [2] 67 96 [2] 73 8d [2] 7c 97 [2] 62 8a [2] 60 8b [2] 7b 8d [2] 67 8a [2] 7b a5 }

  condition:
    any of them
}