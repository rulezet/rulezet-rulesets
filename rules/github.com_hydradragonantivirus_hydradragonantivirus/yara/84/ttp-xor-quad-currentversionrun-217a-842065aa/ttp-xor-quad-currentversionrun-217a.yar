rule TTP_XOR_QUAD_CurrentVersionRun_217a {
  strings:
    $key_217a = { 72 15 [2] 56 1b [2] 7d 37 [2] 53 15 [2] 47 0e [2] 48 14 [2] 56 09 [2] 54 08 [2] 4f 0e [2] 53 09 [2] 4f 26 }

  condition:
    any of them
}