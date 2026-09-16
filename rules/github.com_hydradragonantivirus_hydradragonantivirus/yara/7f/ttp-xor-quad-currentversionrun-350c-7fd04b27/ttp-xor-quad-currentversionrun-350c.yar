rule TTP_XOR_QUAD_CurrentVersionRun_350c {
  strings:
    $key_350c = { 66 63 [2] 42 6d [2] 69 41 [2] 47 63 [2] 53 78 [2] 5c 62 [2] 42 7f [2] 40 7e [2] 5b 78 [2] 47 7f [2] 5b 50 }

  condition:
    any of them
}