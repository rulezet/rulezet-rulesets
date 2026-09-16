rule TTP_XOR_QUAD_CurrentVersionRun_1900 {
  strings:
    $key_1900 = { 4a 6f [2] 6e 61 [2] 45 4d [2] 6b 6f [2] 7f 74 [2] 70 6e [2] 6e 73 [2] 6c 72 [2] 77 74 [2] 6b 73 [2] 77 5c }

  condition:
    any of them
}