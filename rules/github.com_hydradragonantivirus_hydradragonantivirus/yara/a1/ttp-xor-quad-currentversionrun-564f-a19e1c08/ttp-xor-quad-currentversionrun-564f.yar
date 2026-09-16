rule TTP_XOR_QUAD_CurrentVersionRun_564f {
  strings:
    $key_564f = { 05 20 [2] 21 2e [2] 0a 02 [2] 24 20 [2] 30 3b [2] 3f 21 [2] 21 3c [2] 23 3d [2] 38 3b [2] 24 3c [2] 38 13 }

  condition:
    any of them
}