rule TTP_XOR_QUAD_CurrentVersionRun_eb51 {
  strings:
    $key_eb51 = { b8 3e [2] 9c 30 [2] b7 1c [2] 99 3e [2] 8d 25 [2] 82 3f [2] 9c 22 [2] 9e 23 [2] 85 25 [2] 99 22 [2] 85 0d }

  condition:
    any of them
}