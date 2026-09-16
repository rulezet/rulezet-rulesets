rule TTP_XOR_QUAD_CurrentVersionRun_ef29 {
  strings:
    $key_ef29 = { bc 46 [2] 98 48 [2] b3 64 [2] 9d 46 [2] 89 5d [2] 86 47 [2] 98 5a [2] 9a 5b [2] 81 5d [2] 9d 5a [2] 81 75 }

  condition:
    any of them
}