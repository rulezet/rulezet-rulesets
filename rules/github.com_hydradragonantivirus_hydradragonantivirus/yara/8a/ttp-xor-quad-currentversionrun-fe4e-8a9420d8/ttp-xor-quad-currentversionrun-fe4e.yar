rule TTP_XOR_QUAD_CurrentVersionRun_fe4e {
  strings:
    $key_fe4e = { ad 21 [2] 89 2f [2] a2 03 [2] 8c 21 [2] 98 3a [2] 97 20 [2] 89 3d [2] 8b 3c [2] 90 3a [2] 8c 3d [2] 90 12 }

  condition:
    any of them
}