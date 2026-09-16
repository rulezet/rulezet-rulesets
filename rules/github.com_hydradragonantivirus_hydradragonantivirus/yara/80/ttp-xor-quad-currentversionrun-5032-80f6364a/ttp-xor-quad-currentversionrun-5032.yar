rule TTP_XOR_QUAD_CurrentVersionRun_5032 {
  strings:
    $key_5032 = { 03 5d [2] 27 53 [2] 0c 7f [2] 22 5d [2] 36 46 [2] 39 5c [2] 27 41 [2] 25 40 [2] 3e 46 [2] 22 41 [2] 3e 6e }

  condition:
    any of them
}