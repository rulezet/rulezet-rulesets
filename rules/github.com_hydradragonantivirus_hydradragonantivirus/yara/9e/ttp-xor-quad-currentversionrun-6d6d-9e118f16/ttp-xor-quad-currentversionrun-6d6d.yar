rule TTP_XOR_QUAD_CurrentVersionRun_6d6d {
  strings:
    $key_6d6d = { 3e 02 [2] 1a 0c [2] 31 20 [2] 1f 02 [2] 0b 19 [2] 04 03 [2] 1a 1e [2] 18 1f [2] 03 19 [2] 1f 1e [2] 03 31 }

  condition:
    any of them
}