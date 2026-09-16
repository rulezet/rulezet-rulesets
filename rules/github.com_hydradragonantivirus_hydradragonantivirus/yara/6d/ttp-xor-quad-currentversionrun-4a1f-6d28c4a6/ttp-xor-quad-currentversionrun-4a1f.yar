rule TTP_XOR_QUAD_CurrentVersionRun_4a1f {
  strings:
    $key_4a1f = { 19 70 [2] 3d 7e [2] 16 52 [2] 38 70 [2] 2c 6b [2] 23 71 [2] 3d 6c [2] 3f 6d [2] 24 6b [2] 38 6c [2] 24 43 }

  condition:
    any of them
}