rule TTP_XOR_QUAD_CurrentVersionRun_3ffc {
  strings:
    $key_3ffc = { 6c 93 [2] 48 9d [2] 63 b1 [2] 4d 93 [2] 59 88 [2] 56 92 [2] 48 8f [2] 4a 8e [2] 51 88 [2] 4d 8f [2] 51 a0 }

  condition:
    any of them
}