rule TTP_XOR_QUAD_CurrentVersionRun_2705 {
  strings:
    $key_2705 = { 74 6a [2] 50 64 [2] 7b 48 [2] 55 6a [2] 41 71 [2] 4e 6b [2] 50 76 [2] 52 77 [2] 49 71 [2] 55 76 [2] 49 59 }

  condition:
    any of them
}