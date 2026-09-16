rule TTP_XOR_QUAD_CurrentVersionRun_556d {
  strings:
    $key_556d = { 06 02 [2] 22 0c [2] 09 20 [2] 27 02 [2] 33 19 [2] 3c 03 [2] 22 1e [2] 20 1f [2] 3b 19 [2] 27 1e [2] 3b 31 }

  condition:
    any of them
}