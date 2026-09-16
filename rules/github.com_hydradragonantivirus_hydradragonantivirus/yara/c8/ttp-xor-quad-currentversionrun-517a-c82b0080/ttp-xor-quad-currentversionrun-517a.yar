rule TTP_XOR_QUAD_CurrentVersionRun_517a {
  strings:
    $key_517a = { 02 15 [2] 26 1b [2] 0d 37 [2] 23 15 [2] 37 0e [2] 38 14 [2] 26 09 [2] 24 08 [2] 3f 0e [2] 23 09 [2] 3f 26 }

  condition:
    any of them
}