rule TTP_XOR_QUAD_CurrentVersionRun_036c {
  strings:
    $key_036c = { 50 03 [2] 74 0d [2] 5f 21 [2] 71 03 [2] 65 18 [2] 6a 02 [2] 74 1f [2] 76 1e [2] 6d 18 [2] 71 1f [2] 6d 30 }

  condition:
    any of them
}