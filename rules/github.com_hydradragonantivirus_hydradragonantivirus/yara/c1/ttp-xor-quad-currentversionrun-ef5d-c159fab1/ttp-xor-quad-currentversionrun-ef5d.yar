rule TTP_XOR_QUAD_CurrentVersionRun_ef5d {
  strings:
    $key_ef5d = { bc 32 [2] 98 3c [2] b3 10 [2] 9d 32 [2] 89 29 [2] 86 33 [2] 98 2e [2] 9a 2f [2] 81 29 [2] 9d 2e [2] 81 01 }

  condition:
    any of them
}