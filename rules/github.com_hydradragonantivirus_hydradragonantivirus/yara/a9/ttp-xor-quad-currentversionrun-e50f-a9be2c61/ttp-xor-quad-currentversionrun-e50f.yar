rule TTP_XOR_QUAD_CurrentVersionRun_e50f {
  strings:
    $key_e50f = { b6 60 [2] 92 6e [2] b9 42 [2] 97 60 [2] 83 7b [2] 8c 61 [2] 92 7c [2] 90 7d [2] 8b 7b [2] 97 7c [2] 8b 53 }

  condition:
    any of them
}