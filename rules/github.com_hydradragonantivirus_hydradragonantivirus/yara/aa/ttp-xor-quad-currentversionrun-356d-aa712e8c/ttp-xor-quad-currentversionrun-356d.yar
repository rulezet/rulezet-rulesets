rule TTP_XOR_QUAD_CurrentVersionRun_356d {
  strings:
    $key_356d = { 66 02 [2] 42 0c [2] 69 20 [2] 47 02 [2] 53 19 [2] 5c 03 [2] 42 1e [2] 40 1f [2] 5b 19 [2] 47 1e [2] 5b 31 }

  condition:
    any of them
}