rule TTP_XOR_QUAD_CurrentVersionRun_fa26 {
  strings:
    $key_fa26 = { a9 49 [2] 8d 47 [2] a6 6b [2] 88 49 [2] 9c 52 [2] 93 48 [2] 8d 55 [2] 8f 54 [2] 94 52 [2] 88 55 [2] 94 7a }

  condition:
    any of them
}