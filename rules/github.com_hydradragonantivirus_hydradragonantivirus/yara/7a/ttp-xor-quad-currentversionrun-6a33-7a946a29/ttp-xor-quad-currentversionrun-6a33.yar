rule TTP_XOR_QUAD_CurrentVersionRun_6a33 {
  strings:
    $key_6a33 = { 39 5c [2] 1d 52 [2] 36 7e [2] 18 5c [2] 0c 47 [2] 03 5d [2] 1d 40 [2] 1f 41 [2] 04 47 [2] 18 40 [2] 04 6f }

  condition:
    any of them
}