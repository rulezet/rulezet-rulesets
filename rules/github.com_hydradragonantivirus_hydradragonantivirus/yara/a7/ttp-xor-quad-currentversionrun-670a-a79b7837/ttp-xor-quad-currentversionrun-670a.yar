rule TTP_XOR_QUAD_CurrentVersionRun_670a {
  strings:
    $key_670a = { 34 65 [2] 10 6b [2] 3b 47 [2] 15 65 [2] 01 7e [2] 0e 64 [2] 10 79 [2] 12 78 [2] 09 7e [2] 15 79 [2] 09 56 }

  condition:
    any of them
}