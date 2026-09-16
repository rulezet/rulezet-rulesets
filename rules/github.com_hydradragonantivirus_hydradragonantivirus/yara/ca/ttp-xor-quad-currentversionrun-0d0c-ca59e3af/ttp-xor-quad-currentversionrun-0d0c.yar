rule TTP_XOR_QUAD_CurrentVersionRun_0d0c {
  strings:
    $key_0d0c = { 5e 63 [2] 7a 6d [2] 51 41 [2] 7f 63 [2] 6b 78 [2] 64 62 [2] 7a 7f [2] 78 7e [2] 63 78 [2] 7f 7f [2] 63 50 }

  condition:
    any of them
}