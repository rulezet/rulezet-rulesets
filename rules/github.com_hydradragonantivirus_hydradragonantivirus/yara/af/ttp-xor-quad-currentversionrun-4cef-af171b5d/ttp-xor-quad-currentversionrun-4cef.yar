rule TTP_XOR_QUAD_CurrentVersionRun_4cef {
  strings:
    $key_4cef = { 1f 80 [2] 3b 8e [2] 10 a2 [2] 3e 80 [2] 2a 9b [2] 25 81 [2] 3b 9c [2] 39 9d [2] 22 9b [2] 3e 9c [2] 22 b3 }

  condition:
    any of them
}