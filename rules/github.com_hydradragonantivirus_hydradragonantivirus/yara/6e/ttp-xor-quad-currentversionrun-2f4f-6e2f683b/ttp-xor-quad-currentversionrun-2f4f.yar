rule TTP_XOR_QUAD_CurrentVersionRun_2f4f {
  strings:
    $key_2f4f = { 7c 20 [2] 58 2e [2] 73 02 [2] 5d 20 [2] 49 3b [2] 46 21 [2] 58 3c [2] 5a 3d [2] 41 3b [2] 5d 3c [2] 41 13 }

  condition:
    any of them
}