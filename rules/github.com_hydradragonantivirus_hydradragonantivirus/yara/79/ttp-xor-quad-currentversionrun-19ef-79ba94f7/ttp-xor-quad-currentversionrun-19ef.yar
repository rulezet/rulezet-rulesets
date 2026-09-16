rule TTP_XOR_QUAD_CurrentVersionRun_19ef {
  strings:
    $key_19ef = { 4a 80 [2] 6e 8e [2] 45 a2 [2] 6b 80 [2] 7f 9b [2] 70 81 [2] 6e 9c [2] 6c 9d [2] 77 9b [2] 6b 9c [2] 77 b3 }

  condition:
    any of them
}