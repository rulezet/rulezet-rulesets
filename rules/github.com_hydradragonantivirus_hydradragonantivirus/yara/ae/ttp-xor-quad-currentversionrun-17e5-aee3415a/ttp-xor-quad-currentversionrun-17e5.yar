rule TTP_XOR_QUAD_CurrentVersionRun_17e5 {
  strings:
    $key_17e5 = { 44 8a [2] 60 84 [2] 4b a8 [2] 65 8a [2] 71 91 [2] 7e 8b [2] 60 96 [2] 62 97 [2] 79 91 [2] 65 96 [2] 79 b9 }

  condition:
    any of them
}