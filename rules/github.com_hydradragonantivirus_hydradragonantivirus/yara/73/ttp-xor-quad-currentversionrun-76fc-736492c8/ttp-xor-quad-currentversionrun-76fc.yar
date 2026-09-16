rule TTP_XOR_QUAD_CurrentVersionRun_76fc {
  strings:
    $key_76fc = { 25 93 [2] 01 9d [2] 2a b1 [2] 04 93 [2] 10 88 [2] 1f 92 [2] 01 8f [2] 03 8e [2] 18 88 [2] 04 8f [2] 18 a0 }

  condition:
    any of them
}