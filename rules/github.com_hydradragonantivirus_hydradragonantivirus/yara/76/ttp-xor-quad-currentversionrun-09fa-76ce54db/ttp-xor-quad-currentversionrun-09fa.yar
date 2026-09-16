rule TTP_XOR_QUAD_CurrentVersionRun_09fa {
  strings:
    $key_09fa = { 5a 95 [2] 7e 9b [2] 55 b7 [2] 7b 95 [2] 6f 8e [2] 60 94 [2] 7e 89 [2] 7c 88 [2] 67 8e [2] 7b 89 [2] 67 a6 }

  condition:
    any of them
}