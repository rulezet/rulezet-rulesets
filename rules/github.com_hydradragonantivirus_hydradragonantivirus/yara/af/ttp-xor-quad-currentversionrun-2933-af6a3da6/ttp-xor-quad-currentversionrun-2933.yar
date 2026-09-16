rule TTP_XOR_QUAD_CurrentVersionRun_2933 {
  strings:
    $key_2933 = { 7a 5c [2] 5e 52 [2] 75 7e [2] 5b 5c [2] 4f 47 [2] 40 5d [2] 5e 40 [2] 5c 41 [2] 47 47 [2] 5b 40 [2] 47 6f }

  condition:
    any of them
}