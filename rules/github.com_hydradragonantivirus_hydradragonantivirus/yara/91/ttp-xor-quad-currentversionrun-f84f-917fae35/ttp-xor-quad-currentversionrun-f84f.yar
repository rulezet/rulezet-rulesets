rule TTP_XOR_QUAD_CurrentVersionRun_f84f {
  strings:
    $key_f84f = { ab 20 [2] 8f 2e [2] a4 02 [2] 8a 20 [2] 9e 3b [2] 91 21 [2] 8f 3c [2] 8d 3d [2] 96 3b [2] 8a 3c [2] 96 13 }

  condition:
    any of them
}