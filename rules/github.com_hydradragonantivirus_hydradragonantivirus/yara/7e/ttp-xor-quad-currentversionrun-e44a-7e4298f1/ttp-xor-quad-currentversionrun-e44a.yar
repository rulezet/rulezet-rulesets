rule TTP_XOR_QUAD_CurrentVersionRun_e44a {
  strings:
    $key_e44a = { b7 25 [2] 93 2b [2] b8 07 [2] 96 25 [2] 82 3e [2] 8d 24 [2] 93 39 [2] 91 38 [2] 8a 3e [2] 96 39 [2] 8a 16 }

  condition:
    any of them
}