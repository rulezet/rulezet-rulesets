rule TTP_XOR_QUAD_CurrentVersionRun_0800 {
  strings:
    $key_0800 = { 5b 6f [2] 7f 61 [2] 54 4d [2] 7a 6f [2] 6e 74 [2] 61 6e [2] 7f 73 [2] 7d 72 [2] 66 74 [2] 7a 73 [2] 66 5c }

  condition:
    any of them
}