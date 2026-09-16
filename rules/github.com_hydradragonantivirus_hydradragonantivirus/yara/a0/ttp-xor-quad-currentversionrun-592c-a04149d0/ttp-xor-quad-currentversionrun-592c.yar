rule TTP_XOR_QUAD_CurrentVersionRun_592c {
  strings:
    $key_592c = { 0a 43 [2] 2e 4d [2] 05 61 [2] 2b 43 [2] 3f 58 [2] 30 42 [2] 2e 5f [2] 2c 5e [2] 37 58 [2] 2b 5f [2] 37 70 }

  condition:
    any of them
}