rule TTP_XOR_QUAD_CurrentVersionRun_4b51 {
  strings:
    $key_4b51 = { 18 3e [2] 3c 30 [2] 17 1c [2] 39 3e [2] 2d 25 [2] 22 3f [2] 3c 22 [2] 3e 23 [2] 25 25 [2] 39 22 [2] 25 0d }

  condition:
    any of them
}