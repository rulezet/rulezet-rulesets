rule TTP_XOR_QUAD_CurrentVersionRun_0570 {
  strings:
    $key_0570 = { 56 1f [2] 72 11 [2] 59 3d [2] 77 1f [2] 63 04 [2] 6c 1e [2] 72 03 [2] 70 02 [2] 6b 04 [2] 77 03 [2] 6b 2c }

  condition:
    any of them
}