rule TTP_XOR_QUAD_CurrentVersionRun_1bf9 {
  strings:
    $key_1bf9 = { 48 96 [2] 6c 98 [2] 47 b4 [2] 69 96 [2] 7d 8d [2] 72 97 [2] 6c 8a [2] 6e 8b [2] 75 8d [2] 69 8a [2] 75 a5 }

  condition:
    any of them
}