rule TTP_XOR_QUAD_CurrentVersionRun_0e6c {
  strings:
    $key_0e6c = { 5d 03 [2] 79 0d [2] 52 21 [2] 7c 03 [2] 68 18 [2] 67 02 [2] 79 1f [2] 7b 1e [2] 60 18 [2] 7c 1f [2] 60 30 }

  condition:
    any of them
}