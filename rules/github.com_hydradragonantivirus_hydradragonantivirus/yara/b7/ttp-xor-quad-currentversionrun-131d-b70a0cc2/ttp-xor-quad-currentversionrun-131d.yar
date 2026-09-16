rule TTP_XOR_QUAD_CurrentVersionRun_131d {
  strings:
    $key_131d = { 40 72 [2] 64 7c [2] 4f 50 [2] 61 72 [2] 75 69 [2] 7a 73 [2] 64 6e [2] 66 6f [2] 7d 69 [2] 61 6e [2] 7d 41 }

  condition:
    any of them
}