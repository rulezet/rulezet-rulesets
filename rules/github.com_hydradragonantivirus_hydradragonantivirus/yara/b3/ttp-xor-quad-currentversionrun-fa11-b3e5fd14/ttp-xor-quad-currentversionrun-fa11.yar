rule TTP_XOR_QUAD_CurrentVersionRun_fa11 {
  strings:
    $key_fa11 = { a9 7e [2] 8d 70 [2] a6 5c [2] 88 7e [2] 9c 65 [2] 93 7f [2] 8d 62 [2] 8f 63 [2] 94 65 [2] 88 62 [2] 94 4d }

  condition:
    any of them
}