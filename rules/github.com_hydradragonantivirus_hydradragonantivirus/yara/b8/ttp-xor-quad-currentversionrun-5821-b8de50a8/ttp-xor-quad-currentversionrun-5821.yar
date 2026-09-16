rule TTP_XOR_QUAD_CurrentVersionRun_5821 {
  strings:
    $key_5821 = { 0b 4e [2] 2f 40 [2] 04 6c [2] 2a 4e [2] 3e 55 [2] 31 4f [2] 2f 52 [2] 2d 53 [2] 36 55 [2] 2a 52 [2] 36 7d }

  condition:
    any of them
}