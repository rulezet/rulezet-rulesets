rule TTP_XOR_QUAD_CurrentVersionRun_626b {
  strings:
    $key_626b = { 31 04 [2] 15 0a [2] 3e 26 [2] 10 04 [2] 04 1f [2] 0b 05 [2] 15 18 [2] 17 19 [2] 0c 1f [2] 10 18 [2] 0c 37 }

  condition:
    any of them
}