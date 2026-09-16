rule TTP_XOR_QUAD_CurrentVersionRun_fe19 {
  strings:
    $key_fe19 = { ad 76 [2] 89 78 [2] a2 54 [2] 8c 76 [2] 98 6d [2] 97 77 [2] 89 6a [2] 8b 6b [2] 90 6d [2] 8c 6a [2] 90 45 }

  condition:
    any of them
}