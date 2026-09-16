rule TTP_XOR_QUAD_CurrentVersionRun_2110 {
  strings:
    $key_2110 = { 72 7f [2] 56 71 [2] 7d 5d [2] 53 7f [2] 47 64 [2] 48 7e [2] 56 63 [2] 54 62 [2] 4f 64 [2] 53 63 [2] 4f 4c }

  condition:
    any of them
}