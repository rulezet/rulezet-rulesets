rule TTP_XOR_QUAD_CurrentVersionRun_59fc {
  strings:
    $key_59fc = { 0a 93 [2] 2e 9d [2] 05 b1 [2] 2b 93 [2] 3f 88 [2] 30 92 [2] 2e 8f [2] 2c 8e [2] 37 88 [2] 2b 8f [2] 37 a0 }

  condition:
    any of them
}