rule TTP_XOR_QUAD_CurrentVersionRun_ef1e {
  strings:
    $key_ef1e = { bc 71 [2] 98 7f [2] b3 53 [2] 9d 71 [2] 89 6a [2] 86 70 [2] 98 6d [2] 9a 6c [2] 81 6a [2] 9d 6d [2] 81 42 }

  condition:
    any of them
}