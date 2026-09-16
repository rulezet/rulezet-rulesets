rule TTP_XOR_QUAD_CurrentVersionRun_b01c {
  strings:
    $key_b01c = { e3 73 [2] c7 7d [2] ec 51 [2] c2 73 [2] d6 68 [2] d9 72 [2] c7 6f [2] c5 6e [2] de 68 [2] c2 6f [2] de 40 }

  condition:
    any of them
}