rule TTP_XOR_QUAD_CurrentVersionRun_37fc {
  strings:
    $key_37fc = { 64 93 [2] 40 9d [2] 6b b1 [2] 45 93 [2] 51 88 [2] 5e 92 [2] 40 8f [2] 42 8e [2] 59 88 [2] 45 8f [2] 59 a0 }

  condition:
    any of them
}