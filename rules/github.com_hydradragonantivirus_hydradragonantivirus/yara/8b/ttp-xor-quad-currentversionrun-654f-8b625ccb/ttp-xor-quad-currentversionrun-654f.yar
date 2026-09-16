rule TTP_XOR_QUAD_CurrentVersionRun_654f {
  strings:
    $key_654f = { 36 20 [2] 12 2e [2] 39 02 [2] 17 20 [2] 03 3b [2] 0c 21 [2] 12 3c [2] 10 3d [2] 0b 3b [2] 17 3c [2] 0b 13 }

  condition:
    any of them
}