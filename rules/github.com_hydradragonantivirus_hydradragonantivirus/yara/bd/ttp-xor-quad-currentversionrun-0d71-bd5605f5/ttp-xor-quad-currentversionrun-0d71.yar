rule TTP_XOR_QUAD_CurrentVersionRun_0d71 {
  strings:
    $key_0d71 = { 5e 1e [2] 7a 10 [2] 51 3c [2] 7f 1e [2] 6b 05 [2] 64 1f [2] 7a 02 [2] 78 03 [2] 63 05 [2] 7f 02 [2] 63 2d }

  condition:
    any of them
}