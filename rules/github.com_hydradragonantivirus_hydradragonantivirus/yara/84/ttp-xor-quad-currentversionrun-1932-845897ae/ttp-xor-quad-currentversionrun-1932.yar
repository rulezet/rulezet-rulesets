rule TTP_XOR_QUAD_CurrentVersionRun_1932 {
  strings:
    $key_1932 = { 4a 5d [2] 6e 53 [2] 45 7f [2] 6b 5d [2] 7f 46 [2] 70 5c [2] 6e 41 [2] 6c 40 [2] 77 46 [2] 6b 41 [2] 77 6e }

  condition:
    any of them
}