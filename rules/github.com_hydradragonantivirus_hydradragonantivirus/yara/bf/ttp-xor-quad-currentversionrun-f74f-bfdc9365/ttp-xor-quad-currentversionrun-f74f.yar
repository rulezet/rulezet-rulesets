rule TTP_XOR_QUAD_CurrentVersionRun_f74f {
  strings:
    $key_f74f = { a4 20 [2] 80 2e [2] ab 02 [2] 85 20 [2] 91 3b [2] 9e 21 [2] 80 3c [2] 82 3d [2] 99 3b [2] 85 3c [2] 99 13 }

  condition:
    any of them
}