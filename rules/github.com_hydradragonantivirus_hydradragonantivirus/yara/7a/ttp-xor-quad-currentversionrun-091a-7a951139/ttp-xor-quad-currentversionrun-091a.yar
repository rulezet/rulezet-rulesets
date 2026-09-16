rule TTP_XOR_QUAD_CurrentVersionRun_091a {
  strings:
    $key_091a = { 5a 75 [2] 7e 7b [2] 55 57 [2] 7b 75 [2] 6f 6e [2] 60 74 [2] 7e 69 [2] 7c 68 [2] 67 6e [2] 7b 69 [2] 67 46 }

  condition:
    any of them
}