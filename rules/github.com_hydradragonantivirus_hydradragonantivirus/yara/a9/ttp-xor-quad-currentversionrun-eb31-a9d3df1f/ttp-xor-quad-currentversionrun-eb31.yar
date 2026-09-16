rule TTP_XOR_QUAD_CurrentVersionRun_eb31 {
  strings:
    $key_eb31 = { b8 5e [2] 9c 50 [2] b7 7c [2] 99 5e [2] 8d 45 [2] 82 5f [2] 9c 42 [2] 9e 43 [2] 85 45 [2] 99 42 [2] 85 6d }

  condition:
    any of them
}