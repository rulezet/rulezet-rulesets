rule TTP_XOR_QUAD_CurrentVersionRun_540a {
  strings:
    $key_540a = { 07 65 [2] 23 6b [2] 08 47 [2] 26 65 [2] 32 7e [2] 3d 64 [2] 23 79 [2] 21 78 [2] 3a 7e [2] 26 79 [2] 3a 56 }

  condition:
    any of them
}