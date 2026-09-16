rule TTP_XOR_QUAD_CurrentVersionRun_081d {
  strings:
    $key_081d = { 5b 72 [2] 7f 7c [2] 54 50 [2] 7a 72 [2] 6e 69 [2] 61 73 [2] 7f 6e [2] 7d 6f [2] 66 69 [2] 7a 6e [2] 66 41 }

  condition:
    any of them
}