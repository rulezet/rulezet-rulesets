rule TTP_XOR_QUAD_CurrentVersionRun_192c {
  strings:
    $key_192c = { 4a 43 [2] 6e 4d [2] 45 61 [2] 6b 43 [2] 7f 58 [2] 70 42 [2] 6e 5f [2] 6c 5e [2] 77 58 [2] 6b 5f [2] 77 70 }

  condition:
    any of them
}