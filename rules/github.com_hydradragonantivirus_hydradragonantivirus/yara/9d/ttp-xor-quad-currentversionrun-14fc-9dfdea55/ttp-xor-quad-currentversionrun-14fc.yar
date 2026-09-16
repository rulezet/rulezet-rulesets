rule TTP_XOR_QUAD_CurrentVersionRun_14fc {
  strings:
    $key_14fc = { 47 93 [2] 63 9d [2] 48 b1 [2] 66 93 [2] 72 88 [2] 7d 92 [2] 63 8f [2] 61 8e [2] 7a 88 [2] 66 8f [2] 7a a0 }

  condition:
    any of them
}