rule TTP_XOR_QUAD_CurrentVersionRun_627d {
  strings:
    $key_627d = { 31 12 [2] 15 1c [2] 3e 30 [2] 10 12 [2] 04 09 [2] 0b 13 [2] 15 0e [2] 17 0f [2] 0c 09 [2] 10 0e [2] 0c 21 }

  condition:
    any of them
}