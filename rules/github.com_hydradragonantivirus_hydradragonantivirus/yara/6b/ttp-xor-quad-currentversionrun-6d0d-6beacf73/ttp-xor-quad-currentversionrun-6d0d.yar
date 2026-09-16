rule TTP_XOR_QUAD_CurrentVersionRun_6d0d {
  strings:
    $key_6d0d = { 3e 62 [2] 1a 6c [2] 31 40 [2] 1f 62 [2] 0b 79 [2] 04 63 [2] 1a 7e [2] 18 7f [2] 03 79 [2] 1f 7e [2] 03 51 }

  condition:
    any of them
}