rule TTP_XOR_QUAD_CurrentVersionRun_0933 {
  strings:
    $key_0933 = { 5a 5c [2] 7e 52 [2] 55 7e [2] 7b 5c [2] 6f 47 [2] 60 5d [2] 7e 40 [2] 7c 41 [2] 67 47 [2] 7b 40 [2] 67 6f }

  condition:
    any of them
}