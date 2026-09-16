rule TTP_XOR_QUAD_CurrentVersionRun_394f {
  strings:
    $key_394f = { 6a 20 [2] 4e 2e [2] 65 02 [2] 4b 20 [2] 5f 3b [2] 50 21 [2] 4e 3c [2] 4c 3d [2] 57 3b [2] 4b 3c [2] 57 13 }

  condition:
    any of them
}