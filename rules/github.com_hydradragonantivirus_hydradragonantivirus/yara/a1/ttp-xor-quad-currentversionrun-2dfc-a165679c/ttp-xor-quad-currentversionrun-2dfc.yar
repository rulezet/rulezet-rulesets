rule TTP_XOR_QUAD_CurrentVersionRun_2dfc {
  strings:
    $key_2dfc = { 7e 93 [2] 5a 9d [2] 71 b1 [2] 5f 93 [2] 4b 88 [2] 44 92 [2] 5a 8f [2] 58 8e [2] 43 88 [2] 5f 8f [2] 43 a0 }

  condition:
    any of them
}