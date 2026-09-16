rule TTP_XOR_QUAD_CurrentVersionRun_24ba {
  strings:
    $key_24ba = { 77 d5 [2] 53 db [2] 78 f7 [2] 56 d5 [2] 42 ce [2] 4d d4 [2] 53 c9 [2] 51 c8 [2] 4a ce [2] 56 c9 [2] 4a e6 }

  condition:
    any of them
}