rule TTP_XOR_QUAD_CurrentVersionRun_7651 {
  strings:
    $key_7651 = { 25 3e [2] 01 30 [2] 2a 1c [2] 04 3e [2] 10 25 [2] 1f 3f [2] 01 22 [2] 03 23 [2] 18 25 [2] 04 22 [2] 18 0d }

  condition:
    any of them
}