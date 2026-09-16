rule TTP_XOR_QUAD_CurrentVersionRun_1b0c {
  strings:
    $key_1b0c = { 48 63 [2] 6c 6d [2] 47 41 [2] 69 63 [2] 7d 78 [2] 72 62 [2] 6c 7f [2] 6e 7e [2] 75 78 [2] 69 7f [2] 75 50 }

  condition:
    any of them
}