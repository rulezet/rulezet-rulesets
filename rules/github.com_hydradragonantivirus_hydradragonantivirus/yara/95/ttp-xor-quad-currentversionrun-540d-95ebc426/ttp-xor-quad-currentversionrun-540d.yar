rule TTP_XOR_QUAD_CurrentVersionRun_540d {
  strings:
    $key_540d = { 07 62 [2] 23 6c [2] 08 40 [2] 26 62 [2] 32 79 [2] 3d 63 [2] 23 7e [2] 21 7f [2] 3a 79 [2] 26 7e [2] 3a 51 }

  condition:
    any of them
}