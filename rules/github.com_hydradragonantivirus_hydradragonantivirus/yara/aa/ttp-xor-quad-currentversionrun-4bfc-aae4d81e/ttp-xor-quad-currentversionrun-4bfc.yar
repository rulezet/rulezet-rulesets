rule TTP_XOR_QUAD_CurrentVersionRun_4bfc {
  strings:
    $key_4bfc = { 18 93 [2] 3c 9d [2] 17 b1 [2] 39 93 [2] 2d 88 [2] 22 92 [2] 3c 8f [2] 3e 8e [2] 25 88 [2] 39 8f [2] 25 a0 }

  condition:
    any of them
}