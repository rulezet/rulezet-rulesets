rule TTP_XOR_QUAD_CurrentVersionRun_6bfc {
  strings:
    $key_6bfc = { 38 93 [2] 1c 9d [2] 37 b1 [2] 19 93 [2] 0d 88 [2] 02 92 [2] 1c 8f [2] 1e 8e [2] 05 88 [2] 19 8f [2] 05 a0 }

  condition:
    any of them
}