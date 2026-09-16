rule TTP_XOR_QUAD_CurrentVersionRun_096a {
  strings:
    $key_096a = { 5a 05 [2] 7e 0b [2] 55 27 [2] 7b 05 [2] 6f 1e [2] 60 04 [2] 7e 19 [2] 7c 18 [2] 67 1e [2] 7b 19 [2] 67 36 }

  condition:
    any of them
}