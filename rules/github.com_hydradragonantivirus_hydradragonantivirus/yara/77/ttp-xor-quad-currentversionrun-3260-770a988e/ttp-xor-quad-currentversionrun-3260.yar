rule TTP_XOR_QUAD_CurrentVersionRun_3260 {
  strings:
    $key_3260 = { 61 0f [2] 45 01 [2] 6e 2d [2] 40 0f [2] 54 14 [2] 5b 0e [2] 45 13 [2] 47 12 [2] 5c 14 [2] 40 13 [2] 5c 3c }

  condition:
    any of them
}