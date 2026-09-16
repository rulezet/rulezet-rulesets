rule TTP_XOR_QUAD_CurrentVersionRun_6c0c {
  strings:
    $key_6c0c = { 3f 63 [2] 1b 6d [2] 30 41 [2] 1e 63 [2] 0a 78 [2] 05 62 [2] 1b 7f [2] 19 7e [2] 02 78 [2] 1e 7f [2] 02 50 }

  condition:
    any of them
}