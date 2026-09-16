rule TTP_XOR_QUAD_CurrentVersionRun_6d6c {
  strings:
    $key_6d6c = { 3e 03 [2] 1a 0d [2] 31 21 [2] 1f 03 [2] 0b 18 [2] 04 02 [2] 1a 1f [2] 18 1e [2] 03 18 [2] 1f 1f [2] 03 30 }

  condition:
    any of them
}