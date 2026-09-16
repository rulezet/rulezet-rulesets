rule TTP_XOR_QUAD_CurrentVersionRun_2963 {
  strings:
    $key_2963 = { 7a 0c [2] 5e 02 [2] 75 2e [2] 5b 0c [2] 4f 17 [2] 40 0d [2] 5e 10 [2] 5c 11 [2] 47 17 [2] 5b 10 [2] 47 3f }

  condition:
    any of them
}