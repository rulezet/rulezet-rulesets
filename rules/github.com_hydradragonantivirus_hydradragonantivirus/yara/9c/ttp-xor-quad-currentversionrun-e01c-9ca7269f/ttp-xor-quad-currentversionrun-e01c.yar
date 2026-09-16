rule TTP_XOR_QUAD_CurrentVersionRun_e01c {
  strings:
    $key_e01c = { b3 73 [2] 97 7d [2] bc 51 [2] 92 73 [2] 86 68 [2] 89 72 [2] 97 6f [2] 95 6e [2] 8e 68 [2] 92 6f [2] 8e 40 }

  condition:
    any of them
}