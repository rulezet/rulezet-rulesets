rule TTP_XOR_QUAD_CurrentVersionRun_ef00 {
  strings:
    $key_ef00 = { bc 6f [2] 98 61 [2] b3 4d [2] 9d 6f [2] 89 74 [2] 86 6e [2] 98 73 [2] 9a 72 [2] 81 74 [2] 9d 73 [2] 81 5c }

  condition:
    any of them
}