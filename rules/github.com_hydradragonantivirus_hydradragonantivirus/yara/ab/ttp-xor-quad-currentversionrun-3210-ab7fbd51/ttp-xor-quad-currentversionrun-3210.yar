rule TTP_XOR_QUAD_CurrentVersionRun_3210 {
  strings:
    $key_3210 = { 61 7f [2] 45 71 [2] 6e 5d [2] 40 7f [2] 54 64 [2] 5b 7e [2] 45 63 [2] 47 62 [2] 5c 64 [2] 40 63 [2] 5c 4c }

  condition:
    any of them
}