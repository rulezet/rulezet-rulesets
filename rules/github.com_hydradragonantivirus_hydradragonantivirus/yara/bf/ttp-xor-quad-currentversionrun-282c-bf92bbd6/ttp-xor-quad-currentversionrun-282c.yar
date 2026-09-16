rule TTP_XOR_QUAD_CurrentVersionRun_282c {
  strings:
    $key_282c = { 7b 43 [2] 5f 4d [2] 74 61 [2] 5a 43 [2] 4e 58 [2] 41 42 [2] 5f 5f [2] 5d 5e [2] 46 58 [2] 5a 5f [2] 46 70 }

  condition:
    any of them
}