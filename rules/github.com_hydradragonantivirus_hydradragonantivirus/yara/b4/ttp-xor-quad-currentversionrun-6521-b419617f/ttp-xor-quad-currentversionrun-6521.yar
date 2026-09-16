rule TTP_XOR_QUAD_CurrentVersionRun_6521 {
  strings:
    $key_6521 = { 36 4e [2] 12 40 [2] 39 6c [2] 17 4e [2] 03 55 [2] 0c 4f [2] 12 52 [2] 10 53 [2] 0b 55 [2] 17 52 [2] 0b 7d }

  condition:
    any of them
}