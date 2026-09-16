rule TTP_XOR_QUAD_CurrentVersionRun_4971 {
  strings:
    $key_4971 = { 1a 1e [2] 3e 10 [2] 15 3c [2] 3b 1e [2] 2f 05 [2] 20 1f [2] 3e 02 [2] 3c 03 [2] 27 05 [2] 3b 02 [2] 27 2d }

  condition:
    any of them
}