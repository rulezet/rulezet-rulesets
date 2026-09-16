rule TTP_XOR_QUAD_CurrentVersionRun_2f0c {
  strings:
    $key_2f0c = { 7c 63 [2] 58 6d [2] 73 41 [2] 5d 63 [2] 49 78 [2] 46 62 [2] 58 7f [2] 5a 7e [2] 41 78 [2] 5d 7f [2] 41 50 }

  condition:
    any of them
}