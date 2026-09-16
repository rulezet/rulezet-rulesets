rule TTP_XOR_QUAD_CurrentVersionRun_634f {
  strings:
    $key_634f = { 30 20 [2] 14 2e [2] 3f 02 [2] 11 20 [2] 05 3b [2] 0a 21 [2] 14 3c [2] 16 3d [2] 0d 3b [2] 11 3c [2] 0d 13 }

  condition:
    any of them
}