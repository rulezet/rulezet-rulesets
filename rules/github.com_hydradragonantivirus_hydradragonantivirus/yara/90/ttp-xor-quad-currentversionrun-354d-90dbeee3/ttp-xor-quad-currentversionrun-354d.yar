rule TTP_XOR_QUAD_CurrentVersionRun_354d {
  strings:
    $key_354d = { 66 22 [2] 42 2c [2] 69 00 [2] 47 22 [2] 53 39 [2] 5c 23 [2] 42 3e [2] 40 3f [2] 5b 39 [2] 47 3e [2] 5b 11 }

  condition:
    any of them
}