rule TTP_XOR_QUAD_CurrentVersionRun_f2fc {
  strings:
    $key_f2fc = { a1 93 [2] 85 9d [2] ae b1 [2] 80 93 [2] 94 88 [2] 9b 92 [2] 85 8f [2] 87 8e [2] 9c 88 [2] 80 8f [2] 9c a0 }

  condition:
    any of them
}