rule TTP_XOR_QUAD_CurrentVersionRun_ebec {
  strings:
    $key_ebec = { b8 83 [2] 9c 8d [2] b7 a1 [2] 99 83 [2] 8d 98 [2] 82 82 [2] 9c 9f [2] 9e 9e [2] 85 98 [2] 99 9f [2] 85 b0 }

  condition:
    any of them
}