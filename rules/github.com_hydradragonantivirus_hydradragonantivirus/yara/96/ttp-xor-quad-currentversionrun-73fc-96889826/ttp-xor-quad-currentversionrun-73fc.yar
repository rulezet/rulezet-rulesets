rule TTP_XOR_QUAD_CurrentVersionRun_73fc {
  strings:
    $key_73fc = { 20 93 [2] 04 9d [2] 2f b1 [2] 01 93 [2] 15 88 [2] 1a 92 [2] 04 8f [2] 06 8e [2] 1d 88 [2] 01 8f [2] 1d a0 }

  condition:
    any of them
}