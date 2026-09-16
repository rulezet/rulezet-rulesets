rule TTP_XOR_QUAD_CurrentVersionRun_fe26 {
  strings:
    $key_fe26 = { ad 49 [2] 89 47 [2] a2 6b [2] 8c 49 [2] 98 52 [2] 97 48 [2] 89 55 [2] 8b 54 [2] 90 52 [2] 8c 55 [2] 90 7a }

  condition:
    any of them
}