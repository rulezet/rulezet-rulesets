rule TTP_XOR_QUAD_CurrentVersionRun_1111 {
  strings:
    $key_1111 = { 42 7e [2] 66 70 [2] 4d 5c [2] 63 7e [2] 77 65 [2] 78 7f [2] 66 62 [2] 64 63 [2] 7f 65 [2] 63 62 [2] 7f 4d }

  condition:
    any of them
}