rule TTP_XOR_QUAD_CurrentVersionRun_e44c {
  strings:
    $key_e44c = { b7 23 [2] 93 2d [2] b8 01 [2] 96 23 [2] 82 38 [2] 8d 22 [2] 93 3f [2] 91 3e [2] 8a 38 [2] 96 3f [2] 8a 10 }

  condition:
    any of them
}