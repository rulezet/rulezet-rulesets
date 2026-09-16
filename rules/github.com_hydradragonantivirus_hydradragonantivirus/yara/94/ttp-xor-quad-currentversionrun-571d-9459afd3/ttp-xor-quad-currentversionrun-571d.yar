rule TTP_XOR_QUAD_CurrentVersionRun_571d {
  strings:
    $key_571d = { 04 72 [2] 20 7c [2] 0b 50 [2] 25 72 [2] 31 69 [2] 3e 73 [2] 20 6e [2] 22 6f [2] 39 69 [2] 25 6e [2] 39 41 }

  condition:
    any of them
}