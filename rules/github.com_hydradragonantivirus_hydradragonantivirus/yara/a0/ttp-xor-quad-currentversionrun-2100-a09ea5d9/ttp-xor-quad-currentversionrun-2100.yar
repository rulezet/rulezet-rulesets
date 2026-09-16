rule TTP_XOR_QUAD_CurrentVersionRun_2100 {
  strings:
    $key_2100 = { 72 6f [2] 56 61 [2] 7d 4d [2] 53 6f [2] 47 74 [2] 48 6e [2] 56 73 [2] 54 72 [2] 4f 74 [2] 53 73 [2] 4f 5c }

  condition:
    any of them
}