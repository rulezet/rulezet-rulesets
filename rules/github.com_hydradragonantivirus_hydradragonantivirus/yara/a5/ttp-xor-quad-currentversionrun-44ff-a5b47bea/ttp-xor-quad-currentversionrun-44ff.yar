rule TTP_XOR_QUAD_CurrentVersionRun_44ff {
  strings:
    $key_44ff = { 17 90 [2] 33 9e [2] 18 b2 [2] 36 90 [2] 22 8b [2] 2d 91 [2] 33 8c [2] 31 8d [2] 2a 8b [2] 36 8c [2] 2a a3 }

  condition:
    any of them
}