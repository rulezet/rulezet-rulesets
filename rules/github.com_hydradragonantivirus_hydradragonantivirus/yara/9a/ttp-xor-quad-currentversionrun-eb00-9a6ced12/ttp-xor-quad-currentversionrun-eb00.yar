rule TTP_XOR_QUAD_CurrentVersionRun_eb00 {
  strings:
    $key_eb00 = { b8 6f [2] 9c 61 [2] b7 4d [2] 99 6f [2] 8d 74 [2] 82 6e [2] 9c 73 [2] 9e 72 [2] 85 74 [2] 99 73 [2] 85 5c }

  condition:
    any of them
}