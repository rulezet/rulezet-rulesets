rule TTP_XOR_QUAD_CurrentVersionRun_6d0c {
  strings:
    $key_6d0c = { 3e 63 [2] 1a 6d [2] 31 41 [2] 1f 63 [2] 0b 78 [2] 04 62 [2] 1a 7f [2] 18 7e [2] 03 78 [2] 1f 7f [2] 03 50 }

  condition:
    any of them
}