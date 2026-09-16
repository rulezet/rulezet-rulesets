rule TTP_XOR_QUAD_CurrentVersionRun_624d {
  strings:
    $key_624d = { 31 22 [2] 15 2c [2] 3e 00 [2] 10 22 [2] 04 39 [2] 0b 23 [2] 15 3e [2] 17 3f [2] 0c 39 [2] 10 3e [2] 0c 11 }

  condition:
    any of them
}