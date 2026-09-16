rule TTP_XOR_QUAD_CurrentVersionRun_036a {
  strings:
    $key_036a = { 50 05 [2] 74 0b [2] 5f 27 [2] 71 05 [2] 65 1e [2] 6a 04 [2] 74 19 [2] 76 18 [2] 6d 1e [2] 71 19 [2] 6d 36 }

  condition:
    any of them
}