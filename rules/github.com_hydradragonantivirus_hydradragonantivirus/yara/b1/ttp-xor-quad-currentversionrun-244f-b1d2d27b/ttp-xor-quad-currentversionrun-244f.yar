rule TTP_XOR_QUAD_CurrentVersionRun_244f {
  strings:
    $key_244f = { 77 20 [2] 53 2e [2] 78 02 [2] 56 20 [2] 42 3b [2] 4d 21 [2] 53 3c [2] 51 3d [2] 4a 3b [2] 56 3c [2] 4a 13 }

  condition:
    any of them
}