rule TTP_XOR_QUAD_CurrentVersionRun_3bfc {
  strings:
    $key_3bfc = { 68 93 [2] 4c 9d [2] 67 b1 [2] 49 93 [2] 5d 88 [2] 52 92 [2] 4c 8f [2] 4e 8e [2] 55 88 [2] 49 8f [2] 55 a0 }

  condition:
    any of them
}