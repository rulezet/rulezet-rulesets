rule TTP_XOR_QUAD_CurrentVersionRun_307c {
  strings:
    $key_307c = { 63 13 [2] 47 1d [2] 6c 31 [2] 42 13 [2] 56 08 [2] 59 12 [2] 47 0f [2] 45 0e [2] 5e 08 [2] 42 0f [2] 5e 20 }

  condition:
    any of them
}