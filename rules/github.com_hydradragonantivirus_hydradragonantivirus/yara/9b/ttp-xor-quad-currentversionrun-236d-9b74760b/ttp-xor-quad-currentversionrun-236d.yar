rule TTP_XOR_QUAD_CurrentVersionRun_236d {
  strings:
    $key_236d = { 70 02 [2] 54 0c [2] 7f 20 [2] 51 02 [2] 45 19 [2] 4a 03 [2] 54 1e [2] 56 1f [2] 4d 19 [2] 51 1e [2] 4d 31 }

  condition:
    any of them
}