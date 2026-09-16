rule TTP_XOR_QUAD_CurrentVersionRun_4aff {
  strings:
    $key_4aff = { 19 90 [2] 3d 9e [2] 16 b2 [2] 38 90 [2] 2c 8b [2] 23 91 [2] 3d 8c [2] 3f 8d [2] 24 8b [2] 38 8c [2] 24 a3 }

  condition:
    any of them
}