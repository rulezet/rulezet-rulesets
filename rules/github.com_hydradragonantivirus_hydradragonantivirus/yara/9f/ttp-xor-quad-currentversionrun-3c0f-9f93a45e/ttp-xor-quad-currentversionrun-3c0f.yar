rule TTP_XOR_QUAD_CurrentVersionRun_3c0f {
  strings:
    $key_3c0f = { 6f 60 [2] 4b 6e [2] 60 42 [2] 4e 60 [2] 5a 7b [2] 55 61 [2] 4b 7c [2] 49 7d [2] 52 7b [2] 4e 7c [2] 52 53 }

  condition:
    any of them
}