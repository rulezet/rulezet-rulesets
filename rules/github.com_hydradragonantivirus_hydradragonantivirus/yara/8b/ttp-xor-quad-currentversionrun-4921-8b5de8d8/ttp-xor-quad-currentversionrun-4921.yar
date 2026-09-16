rule TTP_XOR_QUAD_CurrentVersionRun_4921 {
  strings:
    $key_4921 = { 1a 4e [2] 3e 40 [2] 15 6c [2] 3b 4e [2] 2f 55 [2] 20 4f [2] 3e 52 [2] 3c 53 [2] 27 55 [2] 3b 52 [2] 27 7d }

  condition:
    any of them
}