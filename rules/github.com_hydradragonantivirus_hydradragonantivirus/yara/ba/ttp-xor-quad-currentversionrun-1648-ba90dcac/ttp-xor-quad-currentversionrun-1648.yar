rule TTP_XOR_QUAD_CurrentVersionRun_1648 {
  strings:
    $key_1648 = { 45 27 [2] 61 29 [2] 4a 05 [2] 64 27 [2] 70 3c [2] 7f 26 [2] 61 3b [2] 63 3a [2] 78 3c [2] 64 3b [2] 78 14 }

  condition:
    any of them
}