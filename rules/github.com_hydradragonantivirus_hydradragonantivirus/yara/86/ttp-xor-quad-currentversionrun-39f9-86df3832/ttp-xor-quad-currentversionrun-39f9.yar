rule TTP_XOR_QUAD_CurrentVersionRun_39f9 {
  strings:
    $key_39f9 = { 6a 96 [2] 4e 98 [2] 65 b4 [2] 4b 96 [2] 5f 8d [2] 50 97 [2] 4e 8a [2] 4c 8b [2] 57 8d [2] 4b 8a [2] 57 a5 }

  condition:
    any of them
}