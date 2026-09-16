rule TTP_XOR_QUAD_CurrentVersionRun_fe68 {
  strings:
    $key_fe68 = { ad 07 [2] 89 09 [2] a2 25 [2] 8c 07 [2] 98 1c [2] 97 06 [2] 89 1b [2] 8b 1a [2] 90 1c [2] 8c 1b [2] 90 34 }

  condition:
    any of them
}