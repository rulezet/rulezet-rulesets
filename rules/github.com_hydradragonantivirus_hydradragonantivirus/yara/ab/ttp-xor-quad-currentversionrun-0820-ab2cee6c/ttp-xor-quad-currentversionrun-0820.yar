rule TTP_XOR_QUAD_CurrentVersionRun_0820 {
  strings:
    $key_0820 = { 5b 4f [2] 7f 41 [2] 54 6d [2] 7a 4f [2] 6e 54 [2] 61 4e [2] 7f 53 [2] 7d 52 [2] 66 54 [2] 7a 53 [2] 66 7c }

  condition:
    any of them
}