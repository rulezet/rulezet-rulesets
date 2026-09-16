rule TTP_XOR_QUAD_CurrentVersionRun_6219 {
  strings:
    $key_6219 = { 31 76 [2] 15 78 [2] 3e 54 [2] 10 76 [2] 04 6d [2] 0b 77 [2] 15 6a [2] 17 6b [2] 0c 6d [2] 10 6a [2] 0c 45 }

  condition:
    any of them
}