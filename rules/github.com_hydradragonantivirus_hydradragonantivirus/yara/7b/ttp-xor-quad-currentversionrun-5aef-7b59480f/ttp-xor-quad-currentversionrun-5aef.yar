rule TTP_XOR_QUAD_CurrentVersionRun_5aef {
  strings:
    $key_5aef = { 09 80 [2] 2d 8e [2] 06 a2 [2] 28 80 [2] 3c 9b [2] 33 81 [2] 2d 9c [2] 2f 9d [2] 34 9b [2] 28 9c [2] 34 b3 }

  condition:
    any of them
}