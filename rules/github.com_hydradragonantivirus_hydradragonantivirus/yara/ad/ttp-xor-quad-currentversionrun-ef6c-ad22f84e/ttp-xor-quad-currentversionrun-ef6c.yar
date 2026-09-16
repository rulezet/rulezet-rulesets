rule TTP_XOR_QUAD_CurrentVersionRun_ef6c {
  strings:
    $key_ef6c = { bc 03 [2] 98 0d [2] b3 21 [2] 9d 03 [2] 89 18 [2] 86 02 [2] 98 1f [2] 9a 1e [2] 81 18 [2] 9d 1f [2] 81 30 }

  condition:
    any of them
}