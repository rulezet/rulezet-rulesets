rule TTP_XOR_QUAD_CurrentVersionRun_624a {
  strings:
    $key_624a = { 31 25 [2] 15 2b [2] 3e 07 [2] 10 25 [2] 04 3e [2] 0b 24 [2] 15 39 [2] 17 38 [2] 0c 3e [2] 10 39 [2] 0c 16 }

  condition:
    any of them
}