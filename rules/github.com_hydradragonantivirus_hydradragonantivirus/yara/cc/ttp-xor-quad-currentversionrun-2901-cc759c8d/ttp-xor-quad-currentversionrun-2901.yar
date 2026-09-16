rule TTP_XOR_QUAD_CurrentVersionRun_2901 {
  strings:
    $key_2901 = { 7a 6e [2] 5e 60 [2] 75 4c [2] 5b 6e [2] 4f 75 [2] 40 6f [2] 5e 72 [2] 5c 73 [2] 47 75 [2] 5b 72 [2] 47 5d }

  condition:
    any of them
}