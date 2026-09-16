rule TTP_XOR_QUAD_CurrentVersionRun_1a20 {
  strings:
    $key_1a20 = { 49 4f [2] 6d 41 [2] 46 6d [2] 68 4f [2] 7c 54 [2] 73 4e [2] 6d 53 [2] 6f 52 [2] 74 54 [2] 68 53 [2] 74 7c }

  condition:
    any of them
}