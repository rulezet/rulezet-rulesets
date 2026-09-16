rule TTP_XOR_QUAD_CurrentVersionRun_636d {
  strings:
    $key_636d = { 30 02 [2] 14 0c [2] 3f 20 [2] 11 02 [2] 05 19 [2] 0a 03 [2] 14 1e [2] 16 1f [2] 0d 19 [2] 11 1e [2] 0d 31 }

  condition:
    any of them
}