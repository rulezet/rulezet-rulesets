rule TTP_XOR_QUAD_CurrentVersionRun_284f {
  strings:
    $key_284f = { 7b 20 [2] 5f 2e [2] 74 02 [2] 5a 20 [2] 4e 3b [2] 41 21 [2] 5f 3c [2] 5d 3d [2] 46 3b [2] 5a 3c [2] 46 13 }

  condition:
    any of them
}