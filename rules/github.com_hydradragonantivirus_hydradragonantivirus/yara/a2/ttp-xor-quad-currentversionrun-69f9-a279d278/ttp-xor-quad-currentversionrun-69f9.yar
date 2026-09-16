rule TTP_XOR_QUAD_CurrentVersionRun_69f9 {
  strings:
    $key_69f9 = { 3a 96 [2] 1e 98 [2] 35 b4 [2] 1b 96 [2] 0f 8d [2] 00 97 [2] 1e 8a [2] 1c 8b [2] 07 8d [2] 1b 8a [2] 07 a5 }

  condition:
    any of them
}