rule TTP_XOR_QUAD_CurrentVersionRun_ef1f {
  strings:
    $key_ef1f = { bc 70 [2] 98 7e [2] b3 52 [2] 9d 70 [2] 89 6b [2] 86 71 [2] 98 6c [2] 9a 6d [2] 81 6b [2] 9d 6c [2] 81 43 }

  condition:
    any of them
}