rule TTP_XOR_QUAD_CurrentVersionRun_1120 {
  strings:
    $key_1120 = { 42 4f [2] 66 41 [2] 4d 6d [2] 63 4f [2] 77 54 [2] 78 4e [2] 66 53 [2] 64 52 [2] 7f 54 [2] 63 53 [2] 7f 7c }

  condition:
    any of them
}