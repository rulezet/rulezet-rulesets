rule TTP_XOR_QUAD_CurrentVersionRun_e44f {
  strings:
    $key_e44f = { b7 20 [2] 93 2e [2] b8 02 [2] 96 20 [2] 82 3b [2] 8d 21 [2] 93 3c [2] 91 3d [2] 8a 3b [2] 96 3c [2] 8a 13 }

  condition:
    any of them
}