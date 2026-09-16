rule TTP_XOR_QUAD_CurrentVersionRun_670d {
  strings:
    $key_670d = { 34 62 [2] 10 6c [2] 3b 40 [2] 15 62 [2] 01 79 [2] 0e 63 [2] 10 7e [2] 12 7f [2] 09 79 [2] 15 7e [2] 09 51 }

  condition:
    any of them
}