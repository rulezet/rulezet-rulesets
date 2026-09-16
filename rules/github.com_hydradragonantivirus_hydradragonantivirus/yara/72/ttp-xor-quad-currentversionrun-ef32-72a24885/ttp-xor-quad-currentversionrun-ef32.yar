rule TTP_XOR_QUAD_CurrentVersionRun_ef32 {
  strings:
    $key_ef32 = { bc 5d [2] 98 53 [2] b3 7f [2] 9d 5d [2] 89 46 [2] 86 5c [2] 98 41 [2] 9a 40 [2] 81 46 [2] 9d 41 [2] 81 6e }

  condition:
    any of them
}