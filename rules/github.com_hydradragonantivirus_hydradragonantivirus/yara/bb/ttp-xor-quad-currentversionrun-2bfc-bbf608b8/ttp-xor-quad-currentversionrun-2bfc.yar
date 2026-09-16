rule TTP_XOR_QUAD_CurrentVersionRun_2bfc {
  strings:
    $key_2bfc = { 78 93 [2] 5c 9d [2] 77 b1 [2] 59 93 [2] 4d 88 [2] 42 92 [2] 5c 8f [2] 5e 8e [2] 45 88 [2] 59 8f [2] 45 a0 }

  condition:
    any of them
}