rule TTP_XOR_QUAD_CurrentVersionRun_1aef {
  strings:
    $key_1aef = { 49 80 [2] 6d 8e [2] 46 a2 [2] 68 80 [2] 7c 9b [2] 73 81 [2] 6d 9c [2] 6f 9d [2] 74 9b [2] 68 9c [2] 74 b3 }

  condition:
    any of them
}