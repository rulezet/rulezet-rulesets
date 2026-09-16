rule TTP_XOR_QUAD_CurrentVersionRun_0aef {
  strings:
    $key_0aef = { 59 80 [2] 7d 8e [2] 56 a2 [2] 78 80 [2] 6c 9b [2] 63 81 [2] 7d 9c [2] 7f 9d [2] 64 9b [2] 78 9c [2] 64 b3 }

  condition:
    any of them
}