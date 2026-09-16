rule TTP_XOR_QUAD_CurrentVersionRun_7d10 {
  strings:
    $key_7d10 = { 2e 7f [2] 0a 71 [2] 21 5d [2] 0f 7f [2] 1b 64 [2] 14 7e [2] 0a 63 [2] 08 62 [2] 13 64 [2] 0f 63 [2] 13 4c }

  condition:
    any of them
}