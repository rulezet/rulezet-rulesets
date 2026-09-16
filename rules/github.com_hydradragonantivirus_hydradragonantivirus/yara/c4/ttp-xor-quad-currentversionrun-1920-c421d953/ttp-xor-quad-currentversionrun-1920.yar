rule TTP_XOR_QUAD_CurrentVersionRun_1920 {
  strings:
    $key_1920 = { 4a 4f [2] 6e 41 [2] 45 6d [2] 6b 4f [2] 7f 54 [2] 70 4e [2] 6e 53 [2] 6c 52 [2] 77 54 [2] 6b 53 [2] 77 7c }

  condition:
    any of them
}