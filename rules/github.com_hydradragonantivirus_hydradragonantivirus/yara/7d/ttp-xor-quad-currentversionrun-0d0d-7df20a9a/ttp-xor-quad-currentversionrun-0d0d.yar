rule TTP_XOR_QUAD_CurrentVersionRun_0d0d {
  strings:
    $key_0d0d = { 5e 62 [2] 7a 6c [2] 51 40 [2] 7f 62 [2] 6b 79 [2] 64 63 [2] 7a 7e [2] 78 7f [2] 63 79 [2] 7f 7e [2] 63 51 }

  condition:
    any of them
}