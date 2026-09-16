rule TTP_XOR_QUAD_CurrentVersionRun_2f4a {
  strings:
    $key_2f4a = { 7c 25 [2] 58 2b [2] 73 07 [2] 5d 25 [2] 49 3e [2] 46 24 [2] 58 39 [2] 5a 38 [2] 41 3e [2] 5d 39 [2] 41 16 }

  condition:
    any of them
}