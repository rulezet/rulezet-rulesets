rule TTP_XOR_QUAD_CurrentVersionRun_ef0e {
  strings:
    $key_ef0e = { bc 61 [2] 98 6f [2] b3 43 [2] 9d 61 [2] 89 7a [2] 86 60 [2] 98 7d [2] 9a 7c [2] 81 7a [2] 9d 7d [2] 81 52 }

  condition:
    any of them
}