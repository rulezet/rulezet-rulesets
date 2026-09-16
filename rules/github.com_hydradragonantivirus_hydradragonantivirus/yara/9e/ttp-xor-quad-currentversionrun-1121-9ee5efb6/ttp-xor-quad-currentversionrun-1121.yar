rule TTP_XOR_QUAD_CurrentVersionRun_1121 {
  strings:
    $key_1121 = { 42 4e [2] 66 40 [2] 4d 6c [2] 63 4e [2] 77 55 [2] 78 4f [2] 66 52 [2] 64 53 [2] 7f 55 [2] 63 52 [2] 7f 7d }

  condition:
    any of them
}