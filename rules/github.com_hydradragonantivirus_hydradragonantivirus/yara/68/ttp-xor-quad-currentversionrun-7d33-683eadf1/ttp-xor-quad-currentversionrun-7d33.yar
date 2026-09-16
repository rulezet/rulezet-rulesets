rule TTP_XOR_QUAD_CurrentVersionRun_7d33 {
  strings:
    $key_7d33 = { 2e 5c [2] 0a 52 [2] 21 7e [2] 0f 5c [2] 1b 47 [2] 14 5d [2] 0a 40 [2] 08 41 [2] 13 47 [2] 0f 40 [2] 13 6f }

  condition:
    any of them
}