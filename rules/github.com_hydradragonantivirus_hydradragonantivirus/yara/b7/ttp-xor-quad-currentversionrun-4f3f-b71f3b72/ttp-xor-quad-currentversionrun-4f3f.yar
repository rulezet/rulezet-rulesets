rule TTP_XOR_QUAD_CurrentVersionRun_4f3f {
  strings:
    $key_4f3f = { 1c 50 [2] 38 5e [2] 13 72 [2] 3d 50 [2] 29 4b [2] 26 51 [2] 38 4c [2] 3a 4d [2] 21 4b [2] 3d 4c [2] 21 63 }

  condition:
    any of them
}