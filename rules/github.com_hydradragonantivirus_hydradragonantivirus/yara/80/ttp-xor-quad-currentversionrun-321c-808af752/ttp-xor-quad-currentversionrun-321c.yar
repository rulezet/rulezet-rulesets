rule TTP_XOR_QUAD_CurrentVersionRun_321c {
  strings:
    $key_321c = { 61 73 [2] 45 7d [2] 6e 51 [2] 40 73 [2] 54 68 [2] 5b 72 [2] 45 6f [2] 47 6e [2] 5c 68 [2] 40 6f [2] 5c 40 }

  condition:
    any of them
}