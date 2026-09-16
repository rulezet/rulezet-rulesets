rule TTP_XOR_QUAD_CurrentVersionRun_fe18 {
  strings:
    $key_fe18 = { ad 77 [2] 89 79 [2] a2 55 [2] 8c 77 [2] 98 6c [2] 97 76 [2] 89 6b [2] 8b 6a [2] 90 6c [2] 8c 6b [2] 90 44 }

  condition:
    any of them
}