rule TTP_XOR_QUAD_CurrentVersionRun_6220 {
  strings:
    $key_6220 = { 31 4f [2] 15 41 [2] 3e 6d [2] 10 4f [2] 04 54 [2] 0b 4e [2] 15 53 [2] 17 52 [2] 0c 54 [2] 10 53 [2] 0c 7c }

  condition:
    any of them
}