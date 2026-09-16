rule TTP_XOR_QUAD_CurrentVersionRun_362f {
  strings:
    $key_362f = { 65 40 [2] 41 4e [2] 6a 62 [2] 44 40 [2] 50 5b [2] 5f 41 [2] 41 5c [2] 43 5d [2] 58 5b [2] 44 5c [2] 58 73 }

  condition:
    any of them
}