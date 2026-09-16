rule TTP_XOR_QUAD_CurrentVersionRun_ef2c {
  strings:
    $key_ef2c = { bc 43 [2] 98 4d [2] b3 61 [2] 9d 43 [2] 89 58 [2] 86 42 [2] 98 5f [2] 9a 5e [2] 81 58 [2] 9d 5f [2] 81 70 }

  condition:
    any of them
}