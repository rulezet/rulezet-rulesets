rule TTP_XOR_QUAD_CurrentVersionRun_104f {
  strings:
    $key_104f = { 43 20 [2] 67 2e [2] 4c 02 [2] 62 20 [2] 76 3b [2] 79 21 [2] 67 3c [2] 65 3d [2] 7e 3b [2] 62 3c [2] 7e 13 }

  condition:
    any of them
}