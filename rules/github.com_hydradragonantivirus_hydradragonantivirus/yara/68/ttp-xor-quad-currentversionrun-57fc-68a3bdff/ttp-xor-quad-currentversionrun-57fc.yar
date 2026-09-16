rule TTP_XOR_QUAD_CurrentVersionRun_57fc {
  strings:
    $key_57fc = { 04 93 [2] 20 9d [2] 0b b1 [2] 25 93 [2] 31 88 [2] 3e 92 [2] 20 8f [2] 22 8e [2] 39 88 [2] 25 8f [2] 39 a0 }

  condition:
    any of them
}