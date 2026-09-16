rule TTP_XOR_QUAD_CurrentVersionRun_3b0c {
  strings:
    $key_3b0c = { 68 63 [2] 4c 6d [2] 67 41 [2] 49 63 [2] 5d 78 [2] 52 62 [2] 4c 7f [2] 4e 7e [2] 55 78 [2] 49 7f [2] 55 50 }

  condition:
    any of them
}