rule TTP_XOR_QUAD_CurrentVersionRun_3000 {
  strings:
    $key_3000 = { 63 6f [2] 47 61 [2] 6c 4d [2] 42 6f [2] 56 74 [2] 59 6e [2] 47 73 [2] 45 72 [2] 5e 74 [2] 42 73 [2] 5e 5c }

  condition:
    any of them
}