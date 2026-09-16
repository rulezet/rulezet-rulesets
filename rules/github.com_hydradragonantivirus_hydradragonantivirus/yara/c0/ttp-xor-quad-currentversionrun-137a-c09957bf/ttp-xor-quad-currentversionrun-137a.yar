rule TTP_XOR_QUAD_CurrentVersionRun_137a {
  strings:
    $key_137a = { 40 15 [2] 64 1b [2] 4f 37 [2] 61 15 [2] 75 0e [2] 7a 14 [2] 64 09 [2] 66 08 [2] 7d 0e [2] 61 09 [2] 7d 26 }

  condition:
    any of them
}