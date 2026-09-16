rule TTP_XOR_QUAD_CurrentVersionRun_1e4f {
  strings:
    $key_1e4f = { 4d 20 [2] 69 2e [2] 42 02 [2] 6c 20 [2] 78 3b [2] 77 21 [2] 69 3c [2] 6b 3d [2] 70 3b [2] 6c 3c [2] 70 13 }

  condition:
    any of them
}