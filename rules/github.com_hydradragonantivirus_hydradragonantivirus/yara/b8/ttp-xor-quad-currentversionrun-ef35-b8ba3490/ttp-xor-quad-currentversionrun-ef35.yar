rule TTP_XOR_QUAD_CurrentVersionRun_ef35 {
  strings:
    $key_ef35 = { bc 5a [2] 98 54 [2] b3 78 [2] 9d 5a [2] 89 41 [2] 86 5b [2] 98 46 [2] 9a 47 [2] 81 41 [2] 9d 46 [2] 81 69 }

  condition:
    any of them
}