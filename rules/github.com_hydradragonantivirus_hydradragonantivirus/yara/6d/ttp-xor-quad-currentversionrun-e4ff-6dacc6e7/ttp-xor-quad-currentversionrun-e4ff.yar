rule TTP_XOR_QUAD_CurrentVersionRun_e4ff {
  strings:
    $key_e4ff = { b7 90 [2] 93 9e [2] b8 b2 [2] 96 90 [2] 82 8b [2] 8d 91 [2] 93 8c [2] 91 8d [2] 8a 8b [2] 96 8c [2] 8a a3 }

  condition:
    any of them
}