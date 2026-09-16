rule TTP_XOR_QUAD_CurrentVersionRun_3a4f {
  strings:
    $key_3a4f = { 69 20 [2] 4d 2e [2] 66 02 [2] 48 20 [2] 5c 3b [2] 53 21 [2] 4d 3c [2] 4f 3d [2] 54 3b [2] 48 3c [2] 54 13 }

  condition:
    any of them
}