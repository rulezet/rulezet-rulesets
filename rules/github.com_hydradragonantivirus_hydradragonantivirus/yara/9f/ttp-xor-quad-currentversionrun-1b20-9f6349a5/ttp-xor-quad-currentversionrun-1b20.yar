rule TTP_XOR_QUAD_CurrentVersionRun_1b20 {
  strings:
    $key_1b20 = { 48 4f [2] 6c 41 [2] 47 6d [2] 69 4f [2] 7d 54 [2] 72 4e [2] 6c 53 [2] 6e 52 [2] 75 54 [2] 69 53 [2] 75 7c }

  condition:
    any of them
}