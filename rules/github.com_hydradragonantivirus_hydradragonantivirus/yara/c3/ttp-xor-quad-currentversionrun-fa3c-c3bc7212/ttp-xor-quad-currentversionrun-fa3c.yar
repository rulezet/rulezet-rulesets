rule TTP_XOR_QUAD_CurrentVersionRun_fa3c {
  strings:
    $key_fa3c = { a9 53 [2] 8d 5d [2] a6 71 [2] 88 53 [2] 9c 48 [2] 93 52 [2] 8d 4f [2] 8f 4e [2] 94 48 [2] 88 4f [2] 94 60 }

  condition:
    any of them
}