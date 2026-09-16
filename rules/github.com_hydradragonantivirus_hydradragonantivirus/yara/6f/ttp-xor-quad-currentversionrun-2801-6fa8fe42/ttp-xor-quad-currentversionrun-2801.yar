rule TTP_XOR_QUAD_CurrentVersionRun_2801 {
  strings:
    $key_2801 = { 7b 6e [2] 5f 60 [2] 74 4c [2] 5a 6e [2] 4e 75 [2] 41 6f [2] 5f 72 [2] 5d 73 [2] 46 75 [2] 5a 72 [2] 46 5d }

  condition:
    any of them
}