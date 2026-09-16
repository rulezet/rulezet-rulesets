rule TTP_XOR_QUAD_CurrentVersionRun_576c {
  strings:
    $key_576c = { 04 03 [2] 20 0d [2] 0b 21 [2] 25 03 [2] 31 18 [2] 3e 02 [2] 20 1f [2] 22 1e [2] 39 18 [2] 25 1f [2] 39 30 }

  condition:
    any of them
}