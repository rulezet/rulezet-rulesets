rule TTP_XOR_QUAD_CurrentVersionRun_eb30 {
  strings:
    $key_eb30 = { b8 5f [2] 9c 51 [2] b7 7d [2] 99 5f [2] 8d 44 [2] 82 5e [2] 9c 43 [2] 9e 42 [2] 85 44 [2] 99 43 [2] 85 6c }

  condition:
    any of them
}