rule TTP_XOR_QUAD_CurrentVersionRun_7810 {
  strings:
    $key_7810 = { 2b 7f [2] 0f 71 [2] 24 5d [2] 0a 7f [2] 1e 64 [2] 11 7e [2] 0f 63 [2] 0d 62 [2] 16 64 [2] 0a 63 [2] 16 4c }

  condition:
    any of them
}