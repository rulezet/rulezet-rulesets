rule TTP_XOR_QUAD_CurrentVersionRun_334f {
  strings:
    $key_334f = { 60 20 [2] 44 2e [2] 6f 02 [2] 41 20 [2] 55 3b [2] 5a 21 [2] 44 3c [2] 46 3d [2] 5d 3b [2] 41 3c [2] 5d 13 }

  condition:
    any of them
}