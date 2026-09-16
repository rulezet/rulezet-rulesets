rule TTP_XOR_QUAD_CurrentVersionRun_622e {
  strings:
    $key_622e = { 31 41 [2] 15 4f [2] 3e 63 [2] 10 41 [2] 04 5a [2] 0b 40 [2] 15 5d [2] 17 5c [2] 0c 5a [2] 10 5d [2] 0c 72 }

  condition:
    any of them
}