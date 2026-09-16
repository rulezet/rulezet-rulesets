rule TTP_XOR_QUAD_CurrentVersionRun_ef05 {
  strings:
    $key_ef05 = { bc 6a [2] 98 64 [2] b3 48 [2] 9d 6a [2] 89 71 [2] 86 6b [2] 98 76 [2] 9a 77 [2] 81 71 [2] 9d 76 [2] 81 59 }

  condition:
    any of them
}