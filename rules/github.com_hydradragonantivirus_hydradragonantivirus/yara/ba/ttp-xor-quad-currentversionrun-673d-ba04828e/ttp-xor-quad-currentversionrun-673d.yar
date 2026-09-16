rule TTP_XOR_QUAD_CurrentVersionRun_673d {
  strings:
    $key_673d = { 34 52 [2] 10 5c [2] 3b 70 [2] 15 52 [2] 01 49 [2] 0e 53 [2] 10 4e [2] 12 4f [2] 09 49 [2] 15 4e [2] 09 61 }

  condition:
    any of them
}