rule TTP_XOR_QUAD_CurrentVersionRun_357f {
  strings:
    $key_357f = { 66 10 [2] 42 1e [2] 69 32 [2] 47 10 [2] 53 0b [2] 5c 11 [2] 42 0c [2] 40 0d [2] 5b 0b [2] 47 0c [2] 5b 23 }

  condition:
    any of them
}