rule TTP_XOR_QUAD_CurrentVersionRun_1afc {
  strings:
    $key_1afc = { 49 93 [2] 6d 9d [2] 46 b1 [2] 68 93 [2] 7c 88 [2] 73 92 [2] 6d 8f [2] 6f 8e [2] 74 88 [2] 68 8f [2] 74 a0 }

  condition:
    any of them
}