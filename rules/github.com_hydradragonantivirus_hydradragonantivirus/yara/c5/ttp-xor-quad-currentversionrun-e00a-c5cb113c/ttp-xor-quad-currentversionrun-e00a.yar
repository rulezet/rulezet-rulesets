rule TTP_XOR_QUAD_CurrentVersionRun_e00a {
  strings:
    $key_e00a = { b3 65 [2] 97 6b [2] bc 47 [2] 92 65 [2] 86 7e [2] 89 64 [2] 97 79 [2] 95 78 [2] 8e 7e [2] 92 79 [2] 8e 56 }

  condition:
    any of them
}