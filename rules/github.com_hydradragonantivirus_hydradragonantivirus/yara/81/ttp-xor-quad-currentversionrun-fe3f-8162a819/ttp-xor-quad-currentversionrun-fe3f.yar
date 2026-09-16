rule TTP_XOR_QUAD_CurrentVersionRun_fe3f {
  strings:
    $key_fe3f = { ad 50 [2] 89 5e [2] a2 72 [2] 8c 50 [2] 98 4b [2] 97 51 [2] 89 4c [2] 8b 4d [2] 90 4b [2] 8c 4c [2] 90 63 }

  condition:
    any of them
}