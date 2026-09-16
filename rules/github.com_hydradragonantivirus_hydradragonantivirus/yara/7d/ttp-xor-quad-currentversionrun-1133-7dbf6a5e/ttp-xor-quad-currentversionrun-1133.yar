rule TTP_XOR_QUAD_CurrentVersionRun_1133 {
  strings:
    $key_1133 = { 42 5c [2] 66 52 [2] 4d 7e [2] 63 5c [2] 77 47 [2] 78 5d [2] 66 40 [2] 64 41 [2] 7f 47 [2] 63 40 [2] 7f 6f }

  condition:
    any of them
}