rule TTP_XOR_QUAD_CurrentVersionRun_f46d {
  strings:
    $key_f46d = { a7 02 [2] 83 0c [2] a8 20 [2] 86 02 [2] 92 19 [2] 9d 03 [2] 83 1e [2] 81 1f [2] 9a 19 [2] 86 1e [2] 9a 31 }

  condition:
    any of them
}