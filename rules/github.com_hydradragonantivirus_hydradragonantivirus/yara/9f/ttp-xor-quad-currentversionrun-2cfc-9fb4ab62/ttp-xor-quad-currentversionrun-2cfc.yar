rule TTP_XOR_QUAD_CurrentVersionRun_2cfc {
  strings:
    $key_2cfc = { 7f 93 [2] 5b 9d [2] 70 b1 [2] 5e 93 [2] 4a 88 [2] 45 92 [2] 5b 8f [2] 59 8e [2] 42 88 [2] 5e 8f [2] 42 a0 }

  condition:
    any of them
}