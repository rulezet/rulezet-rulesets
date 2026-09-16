rule TTP_XOR_QUAD_CurrentVersionRun_fe7e {
  strings:
    $key_fe7e = { ad 11 [2] 89 1f [2] a2 33 [2] 8c 11 [2] 98 0a [2] 97 10 [2] 89 0d [2] 8b 0c [2] 90 0a [2] 8c 0d [2] 90 22 }

  condition:
    any of them
}