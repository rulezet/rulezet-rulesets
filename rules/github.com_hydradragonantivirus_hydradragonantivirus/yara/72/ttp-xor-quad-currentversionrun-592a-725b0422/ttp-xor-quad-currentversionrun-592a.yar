rule TTP_XOR_QUAD_CurrentVersionRun_592a {
  strings:
    $key_592a = { 0a 45 [2] 2e 4b [2] 05 67 [2] 2b 45 [2] 3f 5e [2] 30 44 [2] 2e 59 [2] 2c 58 [2] 37 5e [2] 2b 59 [2] 37 76 }

  condition:
    any of them
}