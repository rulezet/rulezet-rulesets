rule TTP_XOR_QUAD_CurrentVersionRun_0d01 {
  strings:
    $key_0d01 = { 5e 6e [2] 7a 60 [2] 51 4c [2] 7f 6e [2] 6b 75 [2] 64 6f [2] 7a 72 [2] 78 73 [2] 63 75 [2] 7f 72 [2] 63 5d }

  condition:
    any of them
}