rule TTP_XOR_QUAD_CurrentVersionRun_0d1c {
  strings:
    $key_0d1c = { 5e 73 [2] 7a 7d [2] 51 51 [2] 7f 73 [2] 6b 68 [2] 64 72 [2] 7a 6f [2] 78 6e [2] 63 68 [2] 7f 6f [2] 63 40 }

  condition:
    any of them
}