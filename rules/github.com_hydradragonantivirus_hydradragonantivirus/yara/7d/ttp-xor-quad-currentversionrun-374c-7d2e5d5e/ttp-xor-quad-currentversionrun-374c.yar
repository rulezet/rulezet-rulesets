rule TTP_XOR_QUAD_CurrentVersionRun_374c {
  strings:
    $key_374c = { 64 23 [2] 40 2d [2] 6b 01 [2] 45 23 [2] 51 38 [2] 5e 22 [2] 40 3f [2] 42 3e [2] 59 38 [2] 45 3f [2] 59 10 }

  condition:
    any of them
}