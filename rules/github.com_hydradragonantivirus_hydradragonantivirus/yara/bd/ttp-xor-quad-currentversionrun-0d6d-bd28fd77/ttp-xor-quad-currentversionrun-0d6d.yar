rule TTP_XOR_QUAD_CurrentVersionRun_0d6d {
  strings:
    $key_0d6d = { 5e 02 [2] 7a 0c [2] 51 20 [2] 7f 02 [2] 6b 19 [2] 64 03 [2] 7a 1e [2] 78 1f [2] 63 19 [2] 7f 1e [2] 63 31 }

  condition:
    any of them
}