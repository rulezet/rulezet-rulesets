rule TTP_XOR_QUAD_CurrentVersionRun_46fc {
  strings:
    $key_46fc = { 15 93 [2] 31 9d [2] 1a b1 [2] 34 93 [2] 20 88 [2] 2f 92 [2] 31 8f [2] 33 8e [2] 28 88 [2] 34 8f [2] 28 a0 }

  condition:
    any of them
}