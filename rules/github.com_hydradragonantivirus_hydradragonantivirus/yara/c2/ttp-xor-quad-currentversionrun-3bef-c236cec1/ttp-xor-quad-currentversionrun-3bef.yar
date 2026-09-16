rule TTP_XOR_QUAD_CurrentVersionRun_3bef {
  strings:
    $key_3bef = { 68 80 [2] 4c 8e [2] 67 a2 [2] 49 80 [2] 5d 9b [2] 52 81 [2] 4c 9c [2] 4e 9d [2] 55 9b [2] 49 9c [2] 55 b3 }

  condition:
    any of them
}