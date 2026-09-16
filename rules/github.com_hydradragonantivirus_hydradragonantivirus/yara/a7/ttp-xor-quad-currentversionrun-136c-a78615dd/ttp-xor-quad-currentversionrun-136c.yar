rule TTP_XOR_QUAD_CurrentVersionRun_136c {
  strings:
    $key_136c = { 40 03 [2] 64 0d [2] 4f 21 [2] 61 03 [2] 75 18 [2] 7a 02 [2] 64 1f [2] 66 1e [2] 7d 18 [2] 61 1f [2] 7d 30 }

  condition:
    any of them
}