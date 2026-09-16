rule TTP_XOR_QUAD_CurrentVersionRun_146c {
  strings:
    $key_146c = { 47 03 [2] 63 0d [2] 48 21 [2] 66 03 [2] 72 18 [2] 7d 02 [2] 63 1f [2] 61 1e [2] 7a 18 [2] 66 1f [2] 7a 30 }

  condition:
    any of them
}