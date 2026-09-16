rule TTP_XOR_QUAD_CurrentVersionRun_0a60 {
  strings:
    $key_0a60 = { 59 0f [2] 7d 01 [2] 56 2d [2] 78 0f [2] 6c 14 [2] 63 0e [2] 7d 13 [2] 7f 12 [2] 64 14 [2] 78 13 [2] 64 3c }

  condition:
    any of them
}