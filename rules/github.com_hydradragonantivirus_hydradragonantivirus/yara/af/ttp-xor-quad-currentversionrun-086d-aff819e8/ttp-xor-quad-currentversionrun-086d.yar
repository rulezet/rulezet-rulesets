rule TTP_XOR_QUAD_CurrentVersionRun_086d {
  strings:
    $key_086d = { 5b 02 [2] 7f 0c [2] 54 20 [2] 7a 02 [2] 6e 19 [2] 61 03 [2] 7f 1e [2] 7d 1f [2] 66 19 [2] 7a 1e [2] 66 31 }

  condition:
    any of them
}