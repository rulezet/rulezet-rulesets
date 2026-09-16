rule TTP_XOR_QUAD_CurrentVersionRun_fe11 {
  strings:
    $key_fe11 = { ad 7e [2] 89 70 [2] a2 5c [2] 8c 7e [2] 98 65 [2] 97 7f [2] 89 62 [2] 8b 63 [2] 90 65 [2] 8c 62 [2] 90 4d }

  condition:
    any of them
}