rule TTP_XOR_QUAD_CurrentVersionRun_6271 {
  strings:
    $key_6271 = { 31 1e [2] 15 10 [2] 3e 3c [2] 10 1e [2] 04 05 [2] 0b 1f [2] 15 02 [2] 17 03 [2] 0c 05 [2] 10 02 [2] 0c 2d }

  condition:
    any of them
}