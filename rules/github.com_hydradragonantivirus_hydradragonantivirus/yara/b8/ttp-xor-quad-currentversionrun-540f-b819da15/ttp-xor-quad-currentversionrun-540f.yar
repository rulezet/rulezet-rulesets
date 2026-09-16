rule TTP_XOR_QUAD_CurrentVersionRun_540f {
  strings:
    $key_540f = { 07 60 [2] 23 6e [2] 08 42 [2] 26 60 [2] 32 7b [2] 3d 61 [2] 23 7c [2] 21 7d [2] 3a 7b [2] 26 7c [2] 3a 53 }

  condition:
    any of them
}