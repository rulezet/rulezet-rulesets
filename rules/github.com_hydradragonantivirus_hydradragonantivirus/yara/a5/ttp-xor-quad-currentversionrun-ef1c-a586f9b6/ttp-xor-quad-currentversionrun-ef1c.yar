rule TTP_XOR_QUAD_CurrentVersionRun_ef1c {
  strings:
    $key_ef1c = { bc 73 [2] 98 7d [2] b3 51 [2] 9d 73 [2] 89 68 [2] 86 72 [2] 98 6f [2] 9a 6e [2] 81 68 [2] 9d 6f [2] 81 40 }

  condition:
    any of them
}