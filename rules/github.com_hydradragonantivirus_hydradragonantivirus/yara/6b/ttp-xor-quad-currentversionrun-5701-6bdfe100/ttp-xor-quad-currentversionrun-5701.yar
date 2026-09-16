rule TTP_XOR_QUAD_CurrentVersionRun_5701 {
  strings:
    $key_5701 = { 04 6e [2] 20 60 [2] 0b 4c [2] 25 6e [2] 31 75 [2] 3e 6f [2] 20 72 [2] 22 73 [2] 39 75 [2] 25 72 [2] 39 5d }

  condition:
    any of them
}