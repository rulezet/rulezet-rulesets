rule TTP_XOR_QUAD_CurrentVersionRun_350d {
  strings:
    $key_350d = { 66 62 [2] 42 6c [2] 69 40 [2] 47 62 [2] 53 79 [2] 5c 63 [2] 42 7e [2] 40 7f [2] 5b 79 [2] 47 7e [2] 5b 51 }

  condition:
    any of them
}