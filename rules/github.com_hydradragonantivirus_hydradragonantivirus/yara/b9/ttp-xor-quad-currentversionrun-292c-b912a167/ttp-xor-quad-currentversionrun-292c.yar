rule TTP_XOR_QUAD_CurrentVersionRun_292c {
  strings:
    $key_292c = { 7a 43 [2] 5e 4d [2] 75 61 [2] 5b 43 [2] 4f 58 [2] 40 42 [2] 5e 5f [2] 5c 5e [2] 47 58 [2] 5b 5f [2] 47 70 }

  condition:
    any of them
}