rule TTP_XOR_QUAD_CurrentVersionRun_6b4f {
  strings:
    $key_6b4f = { 38 20 [2] 1c 2e [2] 37 02 [2] 19 20 [2] 0d 3b [2] 02 21 [2] 1c 3c [2] 1e 3d [2] 05 3b [2] 19 3c [2] 05 13 }

  condition:
    any of them
}