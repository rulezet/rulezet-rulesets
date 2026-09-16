rule TTP_XOR_QUAD_CurrentVersionRun_fe25 {
  strings:
    $key_fe25 = { ad 4a [2] 89 44 [2] a2 68 [2] 8c 4a [2] 98 51 [2] 97 4b [2] 89 56 [2] 8b 57 [2] 90 51 [2] 8c 56 [2] 90 79 }

  condition:
    any of them
}