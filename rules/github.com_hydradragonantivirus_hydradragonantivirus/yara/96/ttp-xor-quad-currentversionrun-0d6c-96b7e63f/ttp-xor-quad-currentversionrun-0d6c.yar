rule TTP_XOR_QUAD_CurrentVersionRun_0d6c {
  strings:
    $key_0d6c = { 5e 03 [2] 7a 0d [2] 51 21 [2] 7f 03 [2] 6b 18 [2] 64 02 [2] 7a 1f [2] 78 1e [2] 63 18 [2] 7f 1f [2] 63 30 }

  condition:
    any of them
}