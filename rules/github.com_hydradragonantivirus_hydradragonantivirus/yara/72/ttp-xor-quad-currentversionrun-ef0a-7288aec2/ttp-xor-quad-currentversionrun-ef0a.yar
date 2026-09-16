rule TTP_XOR_QUAD_CurrentVersionRun_ef0a {
  strings:
    $key_ef0a = { bc 65 [2] 98 6b [2] b3 47 [2] 9d 65 [2] 89 7e [2] 86 64 [2] 98 79 [2] 9a 78 [2] 81 7e [2] 9d 79 [2] 81 56 }

  condition:
    any of them
}