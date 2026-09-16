rule TTP_XOR_QUAD_CurrentVersionRun_3d4f {
  strings:
    $key_3d4f = { 6e 20 [2] 4a 2e [2] 61 02 [2] 4f 20 [2] 5b 3b [2] 54 21 [2] 4a 3c [2] 48 3d [2] 53 3b [2] 4f 3c [2] 53 13 }

  condition:
    any of them
}