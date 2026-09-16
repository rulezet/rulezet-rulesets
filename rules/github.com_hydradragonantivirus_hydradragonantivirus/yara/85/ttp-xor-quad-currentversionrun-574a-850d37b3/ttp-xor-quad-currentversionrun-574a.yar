rule TTP_XOR_QUAD_CurrentVersionRun_574a {
  strings:
    $key_574a = { 04 25 [2] 20 2b [2] 0b 07 [2] 25 25 [2] 31 3e [2] 3e 24 [2] 20 39 [2] 22 38 [2] 39 3e [2] 25 39 [2] 39 16 }

  condition:
    any of them
}