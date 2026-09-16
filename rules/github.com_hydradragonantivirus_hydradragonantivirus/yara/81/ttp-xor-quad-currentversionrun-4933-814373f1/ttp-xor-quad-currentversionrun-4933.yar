rule TTP_XOR_QUAD_CurrentVersionRun_4933 {
  strings:
    $key_4933 = { 1a 5c [2] 3e 52 [2] 15 7e [2] 3b 5c [2] 2f 47 [2] 20 5d [2] 3e 40 [2] 3c 41 [2] 27 47 [2] 3b 40 [2] 27 6f }

  condition:
    any of them
}