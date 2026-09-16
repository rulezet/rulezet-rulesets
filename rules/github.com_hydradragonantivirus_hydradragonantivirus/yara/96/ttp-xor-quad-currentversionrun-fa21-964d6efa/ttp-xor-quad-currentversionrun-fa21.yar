rule TTP_XOR_QUAD_CurrentVersionRun_fa21 {
  strings:
    $key_fa21 = { a9 4e [2] 8d 40 [2] a6 6c [2] 88 4e [2] 9c 55 [2] 93 4f [2] 8d 52 [2] 8f 53 [2] 94 55 [2] 88 52 [2] 94 7d }

  condition:
    any of them
}