rule TTP_XOR_QUAD_CurrentVersionRun_581d {
  strings:
    $key_581d = { 0b 72 [2] 2f 7c [2] 04 50 [2] 2a 72 [2] 3e 69 [2] 31 73 [2] 2f 6e [2] 2d 6f [2] 36 69 [2] 2a 6e [2] 36 41 }

  condition:
    any of them
}