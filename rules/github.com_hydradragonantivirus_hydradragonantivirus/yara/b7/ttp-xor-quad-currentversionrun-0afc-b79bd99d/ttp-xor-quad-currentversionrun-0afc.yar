rule TTP_XOR_QUAD_CurrentVersionRun_0afc {
  strings:
    $key_0afc = { 59 93 [2] 7d 9d [2] 56 b1 [2] 78 93 [2] 6c 88 [2] 63 92 [2] 7d 8f [2] 7f 8e [2] 64 88 [2] 78 8f [2] 64 a0 }

  condition:
    any of them
}