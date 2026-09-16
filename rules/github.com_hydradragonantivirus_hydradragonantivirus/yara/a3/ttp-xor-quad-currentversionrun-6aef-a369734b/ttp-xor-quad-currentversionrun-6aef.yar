rule TTP_XOR_QUAD_CurrentVersionRun_6aef {
  strings:
    $key_6aef = { 39 80 [2] 1d 8e [2] 36 a2 [2] 18 80 [2] 0c 9b [2] 03 81 [2] 1d 9c [2] 1f 9d [2] 04 9b [2] 18 9c [2] 04 b3 }

  condition:
    any of them
}