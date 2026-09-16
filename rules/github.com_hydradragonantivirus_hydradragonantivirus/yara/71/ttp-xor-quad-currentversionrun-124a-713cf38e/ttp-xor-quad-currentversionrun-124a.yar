rule TTP_XOR_QUAD_CurrentVersionRun_124a {
  strings:
    $key_124a = { 41 25 [2] 65 2b [2] 4e 07 [2] 60 25 [2] 74 3e [2] 7b 24 [2] 65 39 [2] 67 38 [2] 7c 3e [2] 60 39 [2] 7c 16 }

  condition:
    any of them
}