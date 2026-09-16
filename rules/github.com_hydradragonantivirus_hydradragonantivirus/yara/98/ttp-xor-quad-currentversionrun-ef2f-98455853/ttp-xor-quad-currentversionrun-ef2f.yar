rule TTP_XOR_QUAD_CurrentVersionRun_ef2f {
  strings:
    $key_ef2f = { bc 40 [2] 98 4e [2] b3 62 [2] 9d 40 [2] 89 5b [2] 86 41 [2] 98 5c [2] 9a 5d [2] 81 5b [2] 9d 5c [2] 81 73 }

  condition:
    any of them
}