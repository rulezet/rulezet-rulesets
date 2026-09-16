rule TTP_XOR_QUAD_CurrentVersionRun_e64f {
  strings:
    $key_e64f = { b5 20 [2] 91 2e [2] ba 02 [2] 94 20 [2] 80 3b [2] 8f 21 [2] 91 3c [2] 93 3d [2] 88 3b [2] 94 3c [2] 88 13 }

  condition:
    any of them
}