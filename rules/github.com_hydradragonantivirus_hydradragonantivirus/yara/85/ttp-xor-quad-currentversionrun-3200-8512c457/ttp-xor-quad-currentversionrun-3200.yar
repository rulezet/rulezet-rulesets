rule TTP_XOR_QUAD_CurrentVersionRun_3200 {
  strings:
    $key_3200 = { 61 6f [2] 45 61 [2] 6e 4d [2] 40 6f [2] 54 74 [2] 5b 6e [2] 45 73 [2] 47 72 [2] 5c 74 [2] 40 73 [2] 5c 5c }

  condition:
    any of them
}