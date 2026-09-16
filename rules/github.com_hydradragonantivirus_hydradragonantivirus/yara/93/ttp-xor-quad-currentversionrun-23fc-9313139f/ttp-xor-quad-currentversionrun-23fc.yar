rule TTP_XOR_QUAD_CurrentVersionRun_23fc {
  strings:
    $key_23fc = { 70 93 [2] 54 9d [2] 7f b1 [2] 51 93 [2] 45 88 [2] 4a 92 [2] 54 8f [2] 56 8e [2] 4d 88 [2] 51 8f [2] 4d a0 }

  condition:
    any of them
}