rule TTP_XOR_QUAD_CurrentVersionRun_fe6d {
  strings:
    $key_fe6d = { ad 02 [2] 89 0c [2] a2 20 [2] 8c 02 [2] 98 19 [2] 97 03 [2] 89 1e [2] 8b 1f [2] 90 19 [2] 8c 1e [2] 90 31 }

  condition:
    any of them
}