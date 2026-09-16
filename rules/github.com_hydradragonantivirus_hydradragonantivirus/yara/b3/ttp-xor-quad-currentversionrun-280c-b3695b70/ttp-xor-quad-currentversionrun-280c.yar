rule TTP_XOR_QUAD_CurrentVersionRun_280c {
  strings:
    $key_280c = { 7b 63 [2] 5f 6d [2] 74 41 [2] 5a 63 [2] 4e 78 [2] 41 62 [2] 5f 7f [2] 5d 7e [2] 46 78 [2] 5a 7f [2] 46 50 }

  condition:
    any of them
}