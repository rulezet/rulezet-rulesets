rule TTP_XOR_QUAD_CurrentVersionRun_07fc {
  strings:
    $key_07fc = { 54 93 [2] 70 9d [2] 5b b1 [2] 75 93 [2] 61 88 [2] 6e 92 [2] 70 8f [2] 72 8e [2] 69 88 [2] 75 8f [2] 69 a0 }

  condition:
    any of them
}