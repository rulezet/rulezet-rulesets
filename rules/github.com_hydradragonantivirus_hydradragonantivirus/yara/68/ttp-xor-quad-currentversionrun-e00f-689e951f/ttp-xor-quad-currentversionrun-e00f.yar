rule TTP_XOR_QUAD_CurrentVersionRun_e00f {
  strings:
    $key_e00f = { b3 60 [2] 97 6e [2] bc 42 [2] 92 60 [2] 86 7b [2] 89 61 [2] 97 7c [2] 95 7d [2] 8e 7b [2] 92 7c [2] 8e 53 }

  condition:
    any of them
}