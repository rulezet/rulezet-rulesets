rule TTP_XOR_QUAD_CurrentVersionRun_fe2e {
  strings:
    $key_fe2e = { ad 41 [2] 89 4f [2] a2 63 [2] 8c 41 [2] 98 5a [2] 97 40 [2] 89 5d [2] 8b 5c [2] 90 5a [2] 8c 5d [2] 90 72 }

  condition:
    any of them
}