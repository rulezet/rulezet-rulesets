rule TTP_XOR_QUAD_CurrentVersionRun_ef38 {
  strings:
    $key_ef38 = { bc 57 [2] 98 59 [2] b3 75 [2] 9d 57 [2] 89 4c [2] 86 56 [2] 98 4b [2] 9a 4a [2] 81 4c [2] 9d 4b [2] 81 64 }

  condition:
    any of them
}