rule TTP_XOR_QUAD_CurrentVersionRun_6b33 {
  strings:
    $key_6b33 = { 38 5c [2] 1c 52 [2] 37 7e [2] 19 5c [2] 0d 47 [2] 02 5d [2] 1c 40 [2] 1e 41 [2] 05 47 [2] 19 40 [2] 05 6f }

  condition:
    any of them
}