rule TTP_XOR_QUAD_CurrentVersionRun_4c10 {
  strings:
    $key_4c10 = { 1f 7f [2] 3b 71 [2] 10 5d [2] 3e 7f [2] 2a 64 [2] 25 7e [2] 3b 63 [2] 39 62 [2] 22 64 [2] 3e 63 [2] 22 4c }

  condition:
    any of them
}