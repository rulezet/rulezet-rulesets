rule TTP_XOR_QUAD_CurrentVersionRun_0130 {
  strings:
    $key_0130 = { 52 5f [2] 76 51 [2] 5d 7d [2] 73 5f [2] 67 44 [2] 68 5e [2] 76 43 [2] 74 42 [2] 6f 44 [2] 73 43 [2] 6f 6c }

  condition:
    any of them
}