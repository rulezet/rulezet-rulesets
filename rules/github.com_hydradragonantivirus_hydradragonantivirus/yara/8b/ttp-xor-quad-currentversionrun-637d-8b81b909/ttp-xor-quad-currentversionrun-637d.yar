rule TTP_XOR_QUAD_CurrentVersionRun_637d {
  strings:
    $key_637d = { 30 12 [2] 14 1c [2] 3f 30 [2] 11 12 [2] 05 09 [2] 0a 13 [2] 14 0e [2] 16 0f [2] 0d 09 [2] 11 0e [2] 0d 21 }

  condition:
    any of them
}