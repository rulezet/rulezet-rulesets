rule TTP_XOR_QUAD_CurrentVersionRun_354c {
  strings:
    $key_354c = { 66 23 [2] 42 2d [2] 69 01 [2] 47 23 [2] 53 38 [2] 5c 22 [2] 42 3f [2] 40 3e [2] 5b 38 [2] 47 3f [2] 5b 10 }

  condition:
    any of them
}