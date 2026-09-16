rule TTP_XOR_QUAD_CurrentVersionRun_5120 {
  strings:
    $key_5120 = { 02 4f [2] 26 41 [2] 0d 6d [2] 23 4f [2] 37 54 [2] 38 4e [2] 26 53 [2] 24 52 [2] 3f 54 [2] 23 53 [2] 3f 7c }

  condition:
    any of them
}