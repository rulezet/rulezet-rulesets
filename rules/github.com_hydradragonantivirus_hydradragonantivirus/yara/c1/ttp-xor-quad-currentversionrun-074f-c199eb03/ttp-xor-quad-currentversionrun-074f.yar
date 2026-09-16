rule TTP_XOR_QUAD_CurrentVersionRun_074f {
  strings:
    $key_074f = { 54 20 [2] 70 2e [2] 5b 02 [2] 75 20 [2] 61 3b [2] 6e 21 [2] 70 3c [2] 72 3d [2] 69 3b [2] 75 3c [2] 69 13 }

  condition:
    any of them
}