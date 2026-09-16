rule TTP_XOR_QUAD_CurrentVersionRun_2d10 {
  strings:
    $key_2d10 = { 7e 7f [2] 5a 71 [2] 71 5d [2] 5f 7f [2] 4b 64 [2] 44 7e [2] 5a 63 [2] 58 62 [2] 43 64 [2] 5f 63 [2] 43 4c }

  condition:
    any of them
}