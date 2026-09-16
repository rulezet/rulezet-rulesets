rule TTP_XOR_QUAD_CurrentVersionRun_576a {
  strings:
    $key_576a = { 04 05 [2] 20 0b [2] 0b 27 [2] 25 05 [2] 31 1e [2] 3e 04 [2] 20 19 [2] 22 18 [2] 39 1e [2] 25 19 [2] 39 36 }

  condition:
    any of them
}