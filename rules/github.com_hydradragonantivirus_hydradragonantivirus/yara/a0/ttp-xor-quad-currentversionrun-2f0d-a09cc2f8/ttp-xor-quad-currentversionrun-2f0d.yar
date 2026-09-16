rule TTP_XOR_QUAD_CurrentVersionRun_2f0d {
  strings:
    $key_2f0d = { 7c 62 [2] 58 6c [2] 73 40 [2] 5d 62 [2] 49 79 [2] 46 63 [2] 58 7e [2] 5a 7f [2] 41 79 [2] 5d 7e [2] 41 51 }

  condition:
    any of them
}