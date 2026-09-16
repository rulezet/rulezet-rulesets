rule TTP_XOR_QUAD_CurrentVersionRun_542d {
  strings:
    $key_542d = { 07 42 [2] 23 4c [2] 08 60 [2] 26 42 [2] 32 59 [2] 3d 43 [2] 23 5e [2] 21 5f [2] 3a 59 [2] 26 5e [2] 3a 71 }

  condition:
    any of them
}