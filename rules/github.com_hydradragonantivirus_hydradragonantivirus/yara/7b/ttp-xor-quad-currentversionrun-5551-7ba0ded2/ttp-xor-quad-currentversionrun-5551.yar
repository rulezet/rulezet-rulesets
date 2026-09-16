rule TTP_XOR_QUAD_CurrentVersionRun_5551 {
  strings:
    $key_5551 = { 06 3e [2] 22 30 [2] 09 1c [2] 27 3e [2] 33 25 [2] 3c 3f [2] 22 22 [2] 20 23 [2] 3b 25 [2] 27 22 [2] 3b 0d }

  condition:
    any of them
}