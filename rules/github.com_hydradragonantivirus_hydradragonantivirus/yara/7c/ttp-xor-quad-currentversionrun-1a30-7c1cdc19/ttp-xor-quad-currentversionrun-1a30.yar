rule TTP_XOR_QUAD_CurrentVersionRun_1a30 {
  strings:
    $key_1a30 = { 49 5f [2] 6d 51 [2] 46 7d [2] 68 5f [2] 7c 44 [2] 73 5e [2] 6d 43 [2] 6f 42 [2] 74 44 [2] 68 43 [2] 74 6c }

  condition:
    any of them
}