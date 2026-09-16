rule TTP_XOR_QUAD_CurrentVersionRun_f532 {
  strings:
    $key_f532 = { a6 5d [2] 82 53 [2] a9 7f [2] 87 5d [2] 93 46 [2] 9c 5c [2] 82 41 [2] 80 40 [2] 9b 46 [2] 87 41 [2] 9b 6e }

  condition:
    any of them
}