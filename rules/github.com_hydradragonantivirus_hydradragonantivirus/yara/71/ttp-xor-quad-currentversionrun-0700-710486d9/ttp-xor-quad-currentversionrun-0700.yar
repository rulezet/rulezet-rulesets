rule TTP_XOR_QUAD_CurrentVersionRun_0700 {
  strings:
    $key_0700 = { 54 6f [2] 70 61 [2] 5b 4d [2] 75 6f [2] 61 74 [2] 6e 6e [2] 70 73 [2] 72 72 [2] 69 74 [2] 75 73 [2] 69 5c }

  condition:
    any of them
}