rule TTP_XOR_QUAD_CurrentVersionRun_3020 {
  strings:
    $key_3020 = { 63 4f [2] 47 41 [2] 6c 6d [2] 42 4f [2] 56 54 [2] 59 4e [2] 47 53 [2] 45 52 [2] 5e 54 [2] 42 53 [2] 5e 7c }

  condition:
    any of them
}