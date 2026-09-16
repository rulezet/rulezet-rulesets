rule TTP_XOR_QUAD_CurrentVersionRun_1bf8 {
  strings:
    $key_1bf8 = { 48 97 [2] 6c 99 [2] 47 b5 [2] 69 97 [2] 7d 8c [2] 72 96 [2] 6c 8b [2] 6e 8a [2] 75 8c [2] 69 8b [2] 75 a4 }

  condition:
    any of them
}