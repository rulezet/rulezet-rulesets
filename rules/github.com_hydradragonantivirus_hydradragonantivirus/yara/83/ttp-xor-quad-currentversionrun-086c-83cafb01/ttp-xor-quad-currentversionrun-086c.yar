rule TTP_XOR_QUAD_CurrentVersionRun_086c {
  strings:
    $key_086c = { 5b 03 [2] 7f 0d [2] 54 21 [2] 7a 03 [2] 6e 18 [2] 61 02 [2] 7f 1f [2] 7d 1e [2] 66 18 [2] 7a 1f [2] 66 30 }

  condition:
    any of them
}