rule TTP_XOR_QUAD_CurrentVersionRun_016c {
  strings:
    $key_016c = { 52 03 [2] 76 0d [2] 5d 21 [2] 73 03 [2] 67 18 [2] 68 02 [2] 76 1f [2] 74 1e [2] 6f 18 [2] 73 1f [2] 6f 30 }

  condition:
    any of them
}