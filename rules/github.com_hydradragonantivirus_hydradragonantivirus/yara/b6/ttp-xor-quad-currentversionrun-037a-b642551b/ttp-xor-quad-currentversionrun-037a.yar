rule TTP_XOR_QUAD_CurrentVersionRun_037a {
  strings:
    $key_037a = { 50 15 [2] 74 1b [2] 5f 37 [2] 71 15 [2] 65 0e [2] 6a 14 [2] 74 09 [2] 76 08 [2] 6d 0e [2] 71 09 [2] 6d 26 }

  condition:
    any of them
}