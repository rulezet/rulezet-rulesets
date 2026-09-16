rule TTP_XOR_QUAD_CurrentVersionRun_2920 {
  strings:
    $key_2920 = { 7a 4f [2] 5e 41 [2] 75 6d [2] 5b 4f [2] 4f 54 [2] 40 4e [2] 5e 53 [2] 5c 52 [2] 47 54 [2] 5b 53 [2] 47 7c }

  condition:
    any of them
}