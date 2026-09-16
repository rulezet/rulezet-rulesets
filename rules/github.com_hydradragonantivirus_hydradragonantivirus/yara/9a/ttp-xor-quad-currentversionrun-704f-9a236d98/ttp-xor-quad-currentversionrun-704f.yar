rule TTP_XOR_QUAD_CurrentVersionRun_704f {
  strings:
    $key_704f = { 23 20 [2] 07 2e [2] 2c 02 [2] 02 20 [2] 16 3b [2] 19 21 [2] 07 3c [2] 05 3d [2] 1e 3b [2] 02 3c [2] 1e 13 }

  condition:
    any of them
}