rule TTP_XOR_QUAD_CurrentVersionRun_464f {
  strings:
    $key_464f = { 15 20 [2] 31 2e [2] 1a 02 [2] 34 20 [2] 20 3b [2] 2f 21 [2] 31 3c [2] 33 3d [2] 28 3b [2] 34 3c [2] 28 13 }

  condition:
    any of them
}