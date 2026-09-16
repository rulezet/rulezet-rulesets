rule TTP_XOR_QUAD_CurrentVersionRun_54ff {
  strings:
    $key_54ff = { 07 90 [2] 23 9e [2] 08 b2 [2] 26 90 [2] 32 8b [2] 3d 91 [2] 23 8c [2] 21 8d [2] 3a 8b [2] 26 8c [2] 3a a3 }

  condition:
    any of them
}