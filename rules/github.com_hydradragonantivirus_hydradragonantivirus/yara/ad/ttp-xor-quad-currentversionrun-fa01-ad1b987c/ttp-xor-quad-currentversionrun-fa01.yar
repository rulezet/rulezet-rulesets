rule TTP_XOR_QUAD_CurrentVersionRun_fa01 {
  strings:
    $key_fa01 = { a9 6e [2] 8d 60 [2] a6 4c [2] 88 6e [2] 9c 75 [2] 93 6f [2] 8d 72 [2] 8f 73 [2] 94 75 [2] 88 72 [2] 94 5d }

  condition:
    any of them
}