rule TTP_XOR_QUAD_CurrentVersionRun_7a50 {
  strings:
    $key_7a50 = { 29 3f [2] 0d 31 [2] 26 1d [2] 08 3f [2] 1c 24 [2] 13 3e [2] 0d 23 [2] 0f 22 [2] 14 24 [2] 08 23 [2] 14 0c }

  condition:
    any of them
}