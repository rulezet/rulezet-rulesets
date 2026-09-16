rule TTP_XOR_QUAD_CurrentVersionRun_254f {
  strings:
    $key_254f = { 76 20 [2] 52 2e [2] 79 02 [2] 57 20 [2] 43 3b [2] 4c 21 [2] 52 3c [2] 50 3d [2] 4b 3b [2] 57 3c [2] 4b 13 }

  condition:
    any of them
}