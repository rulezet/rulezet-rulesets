rule TTP_XOR_QUAD_CurrentVersionRun_7be5 {
  strings:
    $key_7be5 = { 28 8a [2] 0c 84 [2] 27 a8 [2] 09 8a [2] 1d 91 [2] 12 8b [2] 0c 96 [2] 0e 97 [2] 15 91 [2] 09 96 [2] 15 b9 }

  condition:
    any of them
}