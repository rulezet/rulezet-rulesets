rule TTP_XOR_QUAD_CurrentVersionRun_6a50 {
  strings:
    $key_6a50 = { 39 3f [2] 1d 31 [2] 36 1d [2] 18 3f [2] 0c 24 [2] 03 3e [2] 1d 23 [2] 1f 22 [2] 04 24 [2] 18 23 [2] 04 0c }

  condition:
    any of them
}