rule TTP_XOR_QUAD_CurrentVersionRun_290f {
  strings:
    $key_290f = { 7a 60 [2] 5e 6e [2] 75 42 [2] 5b 60 [2] 4f 7b [2] 40 61 [2] 5e 7c [2] 5c 7d [2] 47 7b [2] 5b 7c [2] 47 53 }

  condition:
    any of them
}