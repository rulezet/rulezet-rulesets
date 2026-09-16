rule TTP_XOR_QUAD_CurrentVersionRun_491b {
  strings:
    $key_491b = { 1a 74 [2] 3e 7a [2] 15 56 [2] 3b 74 [2] 2f 6f [2] 20 75 [2] 3e 68 [2] 3c 69 [2] 27 6f [2] 3b 68 [2] 27 47 }

  condition:
    any of them
}