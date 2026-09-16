rule TTP_XOR_QUAD_CurrentVersionRun_e41d {
  strings:
    $key_e41d = { b7 72 [2] 93 7c [2] b8 50 [2] 96 72 [2] 82 69 [2] 8d 73 [2] 93 6e [2] 91 6f [2] 8a 69 [2] 96 6e [2] 8a 41 }

  condition:
    any of them
}