rule TTP_XOR_QUAD_CurrentVersionRun_ef62 {
  strings:
    $key_ef62 = { bc 0d [2] 98 03 [2] b3 2f [2] 9d 0d [2] 89 16 [2] 86 0c [2] 98 11 [2] 9a 10 [2] 81 16 [2] 9d 11 [2] 81 3e }

  condition:
    any of them
}