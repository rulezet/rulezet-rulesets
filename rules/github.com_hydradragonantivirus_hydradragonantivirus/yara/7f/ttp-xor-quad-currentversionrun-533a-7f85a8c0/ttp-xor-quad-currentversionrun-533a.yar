rule TTP_XOR_QUAD_CurrentVersionRun_533a {
  strings:
    $key_533a = { 00 55 [2] 24 5b [2] 0f 77 [2] 21 55 [2] 35 4e [2] 3a 54 [2] 24 49 [2] 26 48 [2] 3d 4e [2] 21 49 [2] 3d 66 }

  condition:
    any of them
}