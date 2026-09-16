rule TTP_XOR_QUAD_CurrentVersionRun_0c33 {
  strings:
    $key_0c33 = { 5f 5c [2] 7b 52 [2] 50 7e [2] 7e 5c [2] 6a 47 [2] 65 5d [2] 7b 40 [2] 79 41 [2] 62 47 [2] 7e 40 [2] 62 6f }

  condition:
    any of them
}