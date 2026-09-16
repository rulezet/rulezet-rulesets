rule TTP_XOR_QUAD_CurrentVersionRun_304c {
  strings:
    $key_304c = { 63 23 [2] 47 2d [2] 6c 01 [2] 42 23 [2] 56 38 [2] 59 22 [2] 47 3f [2] 45 3e [2] 5e 38 [2] 42 3f [2] 5e 10 }

  condition:
    any of them
}