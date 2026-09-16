rule TTP_XOR_QUAD_CurrentVersionRun_294a {
  strings:
    $key_294a = { 7a 25 [2] 5e 2b [2] 75 07 [2] 5b 25 [2] 4f 3e [2] 40 24 [2] 5e 39 [2] 5c 38 [2] 47 3e [2] 5b 39 [2] 47 16 }

  condition:
    any of them
}