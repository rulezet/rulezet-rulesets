rule TTP_XOR_QUAD_CurrentVersionRun_fe0c {
  strings:
    $key_fe0c = { ad 63 [2] 89 6d [2] a2 41 [2] 8c 63 [2] 98 78 [2] 97 62 [2] 89 7f [2] 8b 7e [2] 90 78 [2] 8c 7f [2] 90 50 }

  condition:
    any of them
}