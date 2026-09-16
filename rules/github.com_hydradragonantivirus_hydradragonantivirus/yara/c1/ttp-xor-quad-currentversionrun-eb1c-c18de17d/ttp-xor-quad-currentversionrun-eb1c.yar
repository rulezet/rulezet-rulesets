rule TTP_XOR_QUAD_CurrentVersionRun_eb1c {
  strings:
    $key_eb1c = { b8 73 [2] 9c 7d [2] b7 51 [2] 99 73 [2] 8d 68 [2] 82 72 [2] 9c 6f [2] 9e 6e [2] 85 68 [2] 99 6f [2] 85 40 }

  condition:
    any of them
}