rule TTP_XOR_QUAD_CurrentVersionRun_620c {
  strings:
    $key_620c = { 31 63 [2] 15 6d [2] 3e 41 [2] 10 63 [2] 04 78 [2] 0b 62 [2] 15 7f [2] 17 7e [2] 0c 78 [2] 10 7f [2] 0c 50 }

  condition:
    any of them
}