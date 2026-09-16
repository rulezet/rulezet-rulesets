rule TTP_XOR_QUAD_CurrentVersionRun_237a {
  strings:
    $key_237a = { 70 15 [2] 54 1b [2] 7f 37 [2] 51 15 [2] 45 0e [2] 4a 14 [2] 54 09 [2] 56 08 [2] 4d 0e [2] 51 09 [2] 4d 26 }

  condition:
    any of them
}