rule TTP_XOR_QUAD_CurrentVersionRun_1410 {
  strings:
    $key_1410 = { 47 7f [2] 63 71 [2] 48 5d [2] 66 7f [2] 72 64 [2] 7d 7e [2] 63 63 [2] 61 62 [2] 7a 64 [2] 66 63 [2] 7a 4c }

  condition:
    any of them
}