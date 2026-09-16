rule TTP_XOR_QUAD_CurrentVersionRun_1cef {
  strings:
    $key_1cef = { 4f 80 [2] 6b 8e [2] 40 a2 [2] 6e 80 [2] 7a 9b [2] 75 81 [2] 6b 9c [2] 69 9d [2] 72 9b [2] 6e 9c [2] 72 b3 }

  condition:
    any of them
}