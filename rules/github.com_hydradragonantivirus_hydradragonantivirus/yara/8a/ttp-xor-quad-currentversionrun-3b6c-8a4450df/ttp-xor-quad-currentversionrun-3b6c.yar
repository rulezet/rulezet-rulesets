rule TTP_XOR_QUAD_CurrentVersionRun_3b6c {
  strings:
    $key_3b6c = { 68 03 [2] 4c 0d [2] 67 21 [2] 49 03 [2] 5d 18 [2] 52 02 [2] 4c 1f [2] 4e 1e [2] 55 18 [2] 49 1f [2] 55 30 }

  condition:
    any of them
}