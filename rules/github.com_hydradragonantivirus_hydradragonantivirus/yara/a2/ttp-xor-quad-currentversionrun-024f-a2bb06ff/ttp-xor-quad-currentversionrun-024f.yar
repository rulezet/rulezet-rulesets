rule TTP_XOR_QUAD_CurrentVersionRun_024f {
  strings:
    $key_024f = { 51 20 [2] 75 2e [2] 5e 02 [2] 70 20 [2] 64 3b [2] 6b 21 [2] 75 3c [2] 77 3d [2] 6c 3b [2] 70 3c [2] 6c 13 }

  condition:
    any of them
}